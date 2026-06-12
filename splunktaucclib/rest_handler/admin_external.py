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
]


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


# Inputs-page guard for classic-cloud SH/SHC where inputs.conf.spec is
# stripped: returns HTTP 200 + empty list + WARN message instead of
# letting RestError surface as splunkd's "Unexpected error" 500.
#
# The leading sentence is the contract that UCC's
# `useInputsAvailability` hook matches on (see
# addonfactory-ucc-generator constants/inputsAvailability.ts); keep
# it verbatim when softening the trailing copy.
INPUTS_UNAVAILABLE_MESSAGE = (
    "Inputs cannot be configured on this Search Head. "
    "Inputs for this add-on must be configured on the Inputs Data Manager "
    "(IDM) instance. For more details, refer to the Splunk Cloud documentation."
)

_DISABLE_GUARD_ENV = "SPLUNKTAUCC_DISABLE_SH_INPUT_GUARD"

_scheme_registered_cache: dict = {}
_sh_instance_cache: dict = {}


def _is_search_head_instance(splunkd_uri, session_key):
    """Returns True (confirmed SH/SHC), False (confirmed not SH/SHC), or None (inconclusive).

    Cached per process. On any error returns None so the scheme probe still
    runs and existing behaviour is preserved for instances where role
    detection cannot be performed.
    """
    key = splunkd_uri or "-"
    if key in _sh_instance_cache:
        return _sh_instance_cache[key]
    try:
        from solnlib.server_info import ServerInfo

        info = ServerInfo.from_server_uri(splunkd_uri, session_key)
        result = info.is_search_head() or info.is_shc_member()
        _sh_instance_cache[key] = result
        return result
    except Exception:
        return None  # inconclusive — do not cache, let scheme probe decide


def _looks_like_scheme_missing(err):
    # Bare 404 or any 5xx looks like a missing scheme; per-entity
    # "does not exist" 404 is a real stanza error and must bubble.
    status = getattr(err, "status", None)
    if status == 404:
        message = (getattr(err, "message", "") or "").lower()
        return "does not exist" not in message
    return isinstance(status, int) and 500 <= status < 600


def _scheme_registered(session_key, app, input_type):
    # Returns True/False/None (None = inconclusive). Cached per process.
    cache_key = (app, input_type)
    if cache_key in _scheme_registered_cache:
        return _scheme_registered_cache[cache_key]
    try:
        from solnlib.splunk_rest_client import SplunkRestClient

        client = SplunkRestClient(
            session_key,
            app=app or "-",
            owner="nobody",
        )
        response = client.get(
            "data/modular-inputs/{}".format(input_type),
            output_mode="json",
        )
        status = getattr(response, "status", None)
        if status == 200:
            _scheme_registered_cache[cache_key] = True
            return True
        if status == 404:
            _scheme_registered_cache[cache_key] = False
            return False
    except Exception as probe_err:
        status = getattr(probe_err, "status", None) or getattr(
            probe_err, "statusCode", None
        )
        if status == 404:
            _scheme_registered_cache[cache_key] = False
            return False
    return None


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
            # list(...) so a generator raises inside this try block.
            if self.callerArgs.id:
                result = list(
                    self.handler.get(
                        self.callerArgs.id,
                        decrypt=decrypt,
                    )
                )
            else:
                result = list(
                    self.handler.all(
                        decrypt=decrypt,
                        count=0,
                    )
                )
        except RestError as err:
            if self._is_input_page_unavailable(err):
                try:
                    confInfo.addWarnMsg(INPUTS_UNAVAILABLE_MESSAGE)
                except Exception:
                    pass
                return []
            raise
        return result

    def _is_input_page_unavailable(self, err):
        # Gate only when: env override is off, the error shape matches a
        # missing scheme/conf, and the endpoint is an inputs endpoint.
        #
        # Primary gate: only fire on SH/SHC instances. If role detection
        # is inconclusive (None) we fall through to the scheme probe so
        # existing behaviour is preserved for non-reachable splunkd.
        # Confirmed non-SH instances (IDM, indexer, Victoria, Noah) are
        # returned False immediately without ever touching the scheme probe.
        if is_true(os.environ.get(_DISABLE_GUARD_ENV, "")):
            return False
        if not _looks_like_scheme_missing(err):
            return False

        is_sh = _is_search_head_instance(
            get_splunkd_endpoint(), self.getSessionKey()
        )
        if is_sh is False:
            # Confirmed non-SH/SHC instance — do not fire the guard.
            return False

        # is_sh is True (confirmed SH/SHC) or None (inconclusive).
        # Continue to scheme probe / conf-name check for the final decision.
        endpoint = self.endpoint
        if isinstance(endpoint, DataInputModel):
            registered = _scheme_registered(
                self.getSessionKey(),
                endpoint.app,
                endpoint.input_type,
            )
            return registered is not True
        if isinstance(endpoint, (SingleModel, MultipleModel)):
            conf_name = (getattr(endpoint, "conf_name", "") or "").lower()
            return "input" in conf_name
        return False

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
