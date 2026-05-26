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


# Stable machine-readable identifier the UCC React UI keys off of to render the
# dedicated "Inputs cannot be configured on this instance" panel instead of the
# generic "Something Went Wrong" error boundary. The code is appended to the
# customer-facing message as ``[code=INPUTS_NOT_ALLOWED_ON_THIS_INSTANCE]`` so
# that any UI which already surfaces ``messages[0].text`` shows the friendly
# copy verbatim, while a UCC-generator update can match the code to render a
# polished panel. Do NOT rename without a coordinated change in
# addonfactory-ucc-generator.
INPUTS_UNAVAILABLE_CODE = "INPUTS_NOT_ALLOWED_ON_THIS_INSTANCE"

# Customer-facing copy. Kept as a template so each TA's display name can be
# substituted by the framework.
INPUTS_UNAVAILABLE_MESSAGE_TEMPLATE = (
    "Inputs cannot be configured on this instance. "
    "You don't have input-page access on this Search Head. "
    "Inputs for {addon} must be configured on the IDM. "
    "Please contact your admin or Splunk Support."
)

# Env-var escape hatch for ops. When set to a truthy value the guard is skipped
# and the original 500 (if any) bubbles up — the previous behavior.
_DISABLE_GUARD_ENV = "SPLUNKTAUCC_DISABLE_SH_INPUT_GUARD"

# Per-process cache for the search-head role determination so the guard does
# not add a REST round-trip to the hot path on healthy instances.
_SEARCH_HEAD_ROLE_CACHE: "dict[str, bool]" = {}

# Status codes / message substrings that indicate "the input scheme is not
# registered on this instance" rather than a legitimate per-entity error. We
# intentionally keep this list narrow so we never mask real 404/409s like
# ``"name does not exist"`` raised by _pre_request().
_INPUT_SCHEME_MISSING_STATUSES = (500, 404, 503)
_INPUT_SCHEME_MISSING_MARKERS = (
    "unknown handler",
    "no handler",
    "could not find",
    "handler not found",
    "no such handler",
    "internal server error",
    "fail to load response",
    "traceback",
)


def _looks_like_scheme_missing(err):
    """Return True if a RestError plausibly comes from a missing input scheme.

    On a Search Head where ``inputs.conf.spec`` is not deployed, splunkd has
    no admin handler registered for ``data/inputs/<type>`` and responds with
    HTTP 5xx (and sometimes 404) bearing an "Unknown handler"-style message.
    By contrast, ``_pre_request`` raises ``RestError(404, "... does not exist")``
    for a legitimate missing entity — that path must NOT trigger the guard.
    """
    if err.status not in _INPUT_SCHEME_MISSING_STATUSES:
        return False
    text = (err.message or "").lower()
    if not text:
        # Bare 5xx with no body is also consistent with the broken-scheme case.
        return err.status >= 500
    if "does not exist" in text or "is already in use" in text:
        return False
    return any(marker in text for marker in _INPUT_SCHEME_MISSING_MARKERS)


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
    """Return True if the current Splunk instance is a Search Head / SHC member.

    Detection is intentionally narrow: a value of True means the input-owner
    roles required to host modular inputs are absent and the input page should
    not attempt to operate. The decision is cached per-process for the lifetime
    of the splunkd worker to avoid extra REST calls on the hot path.

    Any error (network, permission, missing module) is treated as
    "unknown — preserve existing behavior" and returns False so the original
    error surfaces instead of a misleading guard message.
    """
    cache_key = splunkd_uri or "-"
    cached = _SEARCH_HEAD_ROLE_CACHE.get(cache_key)
    if cached is not None:
        return cached

    try:
        from solnlib.server_info import ServerInfo

        info = ServerInfo.from_server_uri(splunkd_uri, session_key)
        is_sh = bool(info.is_search_head() or info.is_shc_member())
    except Exception:
        logger.debug(
            "Failed to determine server role for input-page guard; "
            "preserving existing error behavior.",
            exc_info=True,
        )
        is_sh = False

    _SEARCH_HEAD_ROLE_CACHE[cache_key] = is_sh
    return is_sh


def _build_inputs_unavailable_error(endpoint):
    """Build the friendly RestError shown when inputs cannot be configured.

    Uses HTTP 403 (Forbidden) because the operation is structurally not
    permitted on this instance — not a transient failure. The body is laid
    out so that any client that displays ``messages[0].text`` verbatim shows
    the customer-readable copy first, followed by a stable, parseable code
    suffix used by the UCC React UI to swap in the dedicated panel.
    """
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
            # Force evaluation so we observe any underlying HTTPError now and
            # can translate it before the @build_conf_info decorator iterates.
            result = list(result)
        except RestError as err:
            self._maybe_raise_inputs_unavailable(err)
            raise
        return result

    def _maybe_raise_inputs_unavailable(self, err):
        """Translate a failed inputs lookup into the friendly Search-Head error.

        Triggered only when ALL of the following hold:

        1. The endpoint is a ``DataInputModel`` (i.e. the input page, not a
           configs/settings tab).
        2. The failure shape matches "scheme not registered on this instance"
           (5xx / 404 with no body or a known "Unknown handler" marker), so
           legitimate per-entity errors like "name does not exist" continue
           to surface as-is.
        3. The guard has not been disabled via
           ``SPLUNKTAUCC_DISABLE_SH_INPUT_GUARD``.
        4. The running instance is detected as a Search Head / SHC member.

        On Heavy Forwarders / IDMs (or whenever any of the above is false)
        the original error is re-raised unchanged, so existing behavior on
        input-owning instances is preserved.
        """
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
            logger.debug(
                "Could not resolve splunkd context for input-page guard.",
                exc_info=True,
            )
            return
        if not _is_search_head_instance(splunkd_uri, session_key):
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
