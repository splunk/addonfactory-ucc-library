#
# Copyright 2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


import logging
import os
from functools import wraps

from solnlib.splunkenv import get_splunkd_uri
from solnlib.utils import is_true
from splunk import admin

from .eai import EAI_FIELDS
from .endpoint import DataInputModel, MultipleModel, SingleModel
from .error import RestError
from .handler import RestHandler

try:
    from custom_hook_mixin import CustomHookMixin as HookMixin
except ImportError:
    from .base_hook_mixin import BaseHookMixin as HookMixin


__all__ = [
    "make_conf_item",
    "build_conf_info",
    "AdminExternalHandler",
    "INPUTS_UNAVAILABLE_CODE",
    "INPUTS_UNAVAILABLE_MESSAGE_TEMPLATE",
]


logger = logging.getLogger(__name__)


INPUTS_UNAVAILABLE_CODE = "INPUTS_NOT_ALLOWED_ON_THIS_INSTANCE"

INPUTS_UNAVAILABLE_MESSAGE_TEMPLATE = (
    "Inputs cannot be configured on this instance. "
    "You don't have input-page access on this Search Head. "
    "Inputs for {addon} must be configured on the IDM. "
    "Please contact your admin or Splunk Support."
)

_DISABLE_GUARD_ENV = "SPLUNKTAUCC_DISABLE_SH_INPUT_GUARD"

_SEARCH_HEAD_ROLE_CACHE: "dict[str, bool]" = {}

# Per-process cache of "is this modular input scheme registered on this
# instance?" keyed by (splunkd_uri, app, kind). None means "could not
# determine" and is never cached.
_SCHEME_REGISTERED_CACHE: "dict[tuple, bool]" = {}

# Roles that own inputs; presence of any of these means the instance can host
# inputs locally and the guard must NOT fire even if it is also a search head
# (e.g. dev all-in-one boxes).
_INPUT_OWNER_ROLES = frozenset(
    {
        "indexer",
        "cluster_slave",
        "cluster_peer",
        "heavyweight_forwarder",
        "lightweight_forwarder",
        "universal_forwarder",
    }
)


def _looks_like_scheme_missing(err):
    """True when a RestError looks like the input scheme is not registered
    on this instance, rather than a legitimate per-entity API error."""
    if err.status >= 500:
        return True
    if err.status == 404:
        text = (err.message or "").lower()
        if "does not exist" in text or "is already in use" in text:
            return False
        return True
    return False


def make_conf_item(conf_item, content, eai):
    for key, val in content.items():
        conf_item[key] = val

    for eai_field in EAI_FIELDS:
        conf_item.setMetadata(eai_field, eai.content[eai_field])

    return conf_item


def build_conf_info(meth):
    """
    Build conf info for admin external REST endpoint.

    :param meth:
    :return:
    """

    @wraps(meth)
    def wrapper(self, confInfo):
        result = meth(self, confInfo)
        for entity in result:
            make_conf_item(
                confInfo[entity.name],
                entity.content,
                entity.eai,
            )

    return wrapper


def get_splunkd_endpoint():
    if os.environ.get("SPLUNKD_URI"):
        return os.environ["SPLUNKD_URI"]
    else:
        splunkd_uri = get_splunkd_uri()
        os.environ["SPLUNKD_URI"] = splunkd_uri
        return splunkd_uri


def _is_search_head_instance(splunkd_uri, session_key):
    """True iff this instance is a search-head-only role (no input-owner
    role present). Cached per-process. Returns False on any error so the
    original behavior is preserved when role detection cannot be performed."""
    cache_key = splunkd_uri or "-"
    cached = _SEARCH_HEAD_ROLE_CACHE.get(cache_key)
    if cached is not None:
        return cached

    try:
        from solnlib.server_info import ServerInfo

        info = ServerInfo.from_server_uri(splunkd_uri, session_key)
        if info.is_search_head() or info.is_shc_member():
            roles = set(info.to_dict().get("server_roles", []))
            is_sh = not (_INPUT_OWNER_ROLES & roles)
        else:
            is_sh = False
    except Exception:
        logger.debug("Server role lookup failed", exc_info=True)
        return False

    _SEARCH_HEAD_ROLE_CACHE[cache_key] = is_sh
    return is_sh


def _scheme_registered(splunkd_uri, session_key, app, kind):
    """Return True/False if we can verify modular-input scheme registration,
    or None when the check itself fails. Cached per (uri, app, kind)."""
    cache_key = (splunkd_uri or "-", app or "-", kind or "-")
    if cache_key in _SCHEME_REGISTERED_CACHE:
        return _SCHEME_REGISTERED_CACHE[cache_key]

    try:
        import urllib.parse

        from solnlib.splunk_rest_client import SplunkRestClient
        from splunklib import binding

        parts = urllib.parse.urlparse(splunkd_uri)
        client = SplunkRestClient(
            session_key,
            app,
            owner="nobody",
            scheme=parts.scheme,
            host=parts.hostname,
            port=parts.port,
        )
        try:
            client.get(f"data/modular-inputs/{kind}")
            registered = True
        except binding.HTTPError as exc:
            if exc.status == 404:
                registered = False
            else:
                return None
    except Exception:
        logger.debug("Scheme-registered lookup failed", exc_info=True)
        return None

    _SCHEME_REGISTERED_CACHE[cache_key] = registered
    return registered


def _build_inputs_unavailable_error(endpoint):
    addon = (
        f'the Splunk Add-on "{endpoint.app}"'
        if getattr(endpoint, "app", None)
        else "this add-on"
    )
    message = (
        INPUTS_UNAVAILABLE_MESSAGE_TEMPLATE.format(addon=addon)
        + f" [code={INPUTS_UNAVAILABLE_CODE}]"
    )
    return RestError(403, message)


class AdminExternalHandler(HookMixin, admin.MConfigHandler):

    # Leave it for setting REST model
    endpoint = None

    # action parameter for getting clear credentials
    ACTION_CRED = "--cred--"

    def __init__(self, *args, **kwargs):
        # use classic inheritance to be compatible for
        # old version of Splunk private SDK
        admin.MConfigHandler.__init__(self, *args, **kwargs)
        self.handler = RestHandler(
            get_splunkd_endpoint(),
            self.getSessionKey(),
            self.endpoint,
        )
        self.payload = self._convert_payload()

    def setup(self):
        # add args for getting clear credentials
        if self.requestedAction == admin.ACTION_LIST:
            self.supportedArgs.addOptArg(self.ACTION_CRED)

        # add args in payload while creating/updating
        actions = (admin.ACTION_LIST, admin.ACTION_REMOVE)
        if self.requestedAction in actions:
            return
        model = self.endpoint.model(self.callerArgs.id)
        if self.requestedAction == admin.ACTION_CREATE:
            for field in model.fields:
                if field.required:
                    self.supportedArgs.addReqArg(field.name)
                else:
                    self.supportedArgs.addOptArg(field.name)

        if self.requestedAction == admin.ACTION_EDIT:
            for field in model.fields:
                self.supportedArgs.addOptArg(field.name)

    @build_conf_info
    def handleList(self, confInfo):
        decrypt = self.callerArgs.data.get(
            self.ACTION_CRED,
            [False],
        )
        decrypt = is_true(decrypt[0])
        try:
            if self.callerArgs.id:
                result = self.handler.get(
                    self.callerArgs.id,
                    decrypt=decrypt,
                )
            else:
                result = self.handler.all(
                    decrypt=decrypt,
                    count=0,
                )
            if isinstance(self.endpoint, DataInputModel):
                result = list(result)
        except RestError as err:
            self._maybe_raise_inputs_unavailable(err)
            raise
        return result

    def _maybe_raise_inputs_unavailable(self, err):
        if not isinstance(self.endpoint, DataInputModel):
            return
        if not _looks_like_scheme_missing(err):
            return
        if is_true(os.environ.get(_DISABLE_GUARD_ENV, "")):
            return
        try:
            splunkd_uri = get_splunkd_endpoint()
            session_key = self.getSessionKey()
        except Exception:
            return
        if not _is_search_head_instance(splunkd_uri, session_key):
            return
        # If we can verify the modinput scheme IS registered, treat the 5xx
        # as a real transient error and let it surface. Only when the scheme
        # is verifiably missing (False) or unverifiable (None) do we show
        # the friendly message.
        app = getattr(self.endpoint, "app", None)
        kind = getattr(self.endpoint, "input_type", None)
        if _scheme_registered(splunkd_uri, session_key, app, kind) is True:
            return
        raise _build_inputs_unavailable_error(self.endpoint)

    @build_conf_info
    def handleCreate(self, confInfo):
        self.create_hook(
            session_key=self.getSessionKey(),
            config_name=self._get_name(),
            stanza_id=self.callerArgs.id,
            payload=self.payload,
        )
        return self.handler.create(
            self.callerArgs.id,
            self.payload,
        )

    @build_conf_info
    def handleEdit(self, confInfo):
        disabled = self.payload.get("disabled")
        if disabled is None:
            self.edit_hook(
                session_key=self.getSessionKey(),
                config_name=self._get_name(),
                stanza_id=self.callerArgs.id,
                payload=self.payload,
            )
            return self.handler.update(
                self.callerArgs.id,
                self.payload,
            )
        elif is_true(disabled):
            return self.handler.disable(self.callerArgs.id)
        else:
            return self.handler.enable(self.callerArgs.id)

    @build_conf_info
    def handleRemove(self, confInfo):
        self.delete_hook(
            session_key=self.getSessionKey(),
            config_name=self._get_name(),
            stanza_id=self.callerArgs.id,
        )
        return self.handler.delete(self.callerArgs.id)

    def _get_name(self):
        name = None
        if isinstance(self.handler.get_endpoint(), DataInputModel):
            name = self.handler.get_endpoint().input_type
        elif isinstance(self.handler.get_endpoint(), SingleModel):
            name = self.handler.get_endpoint().config_name
        elif isinstance(self.handler.get_endpoint(), MultipleModel):
            # For multiple model, the configuraiton name is same with stanza id
            name = self.callerArgs.id
        return name

    def _convert_payload(self):
        check_actions = (admin.ACTION_CREATE, admin.ACTION_EDIT)
        if self.requestedAction not in check_actions:
            return None

        payload = {}
        for filed, value in self.callerArgs.data.items():
            payload[filed] = value[0] if value and value[0] else ""
        return payload


def handle(
    endpoint,
    handler=AdminExternalHandler,
    context_info=admin.CONTEXT_APP_ONLY,
):
    """
    Handle request.

    :param endpoint: REST endpoint
    :param handler: REST handler
    :param context_info:
    :return:
    """
    real_handler = type(
        handler.__name__,
        (handler,),
        {"endpoint": endpoint},
    )
    admin.init(real_handler, ctxInfo=context_info)
