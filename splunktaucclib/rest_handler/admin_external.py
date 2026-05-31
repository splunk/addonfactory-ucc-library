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


# Search-head input-page guard.
#
# On classic-cloud Search Heads / SHCs the inputs.conf.spec for cloud TAs
# (AWS, GCP, MSCS, ...) is stripped at deploy time, so splunkd has no
# scheme registered for the input type. The UCC-generated REST endpoint
# then returns HTTP 404, splunktaucclib raises RestError(404), and
# splunk.admin.MConfigHandler -- which does not recognise RestError --
# wraps it as HTTP 500
# "Unexpected error '<class RestError>' from python handler ...".
# The UCC React UI surfaces that 500 as the global "Something Went Wrong"
# overlay. Cloud testing on Splunk_TA_google-cloudplatform confirmed:
#   * splunk.RESTException is ALSO wrapped as "Unexpected error" -- so
#     re-raising any exception keeps the page broken.
#   * solnlib server-role detection is not reliable on Splunk Cloud
#     managed SHs (mixed roles, edge cases with no roles at all), so a
#     role-based gate produced false negatives in production.
# This guard therefore returns HTTP 200 with an empty entry list plus a
# WARN message in confInfo. splunkd renders that as a clean response
# (entry=[] and messages=[{"type":"WARN","text":"..."}]), the UCC UI
# shows the endpoint's normal empty state, and any consumer reading
# `messages[]` still sees the friendly text.
INPUTS_UNAVAILABLE_MESSAGE = (
    "Inputs cannot be configured on this instance. "
    "You don't have input-page access on this Search Head. "
    "Inputs for this add-on must be configured on the IDM. "
    "Please contact your admin or Splunk Support."
)

_DISABLE_GUARD_ENV = "SPLUNKTAUCC_DISABLE_SH_INPUT_GUARD"

_scheme_registered_cache: dict = {}


def _looks_like_scheme_missing(err):
    """Return True if `err` looks like the input scheme/conf is missing.

    A bare 404 from splunkd (or any 5xx) matches; the per-entity
    "does not exist" 404 raised when a stanza is genuinely missing
    must bubble unchanged so the UI can show the right message for that.
    """
    status = getattr(err, "status", None)
    if status == 404:
        message = (getattr(err, "message", "") or "").lower()
        return "does not exist" not in message
    return isinstance(status, int) and 500 <= status < 600


def _scheme_registered(session_key, app, input_type):
    """Probe splunkd to determine whether the modular-input scheme exists.

    Returns True when registered, False when confirmed missing, and None
    when the probe is inconclusive (transient splunkd / network error).
    Cached per (app, input_type) for the life of the handler process.
    """
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
            # list(...) forces eager evaluation inside the try block;
            # the underlying handler may return a generator, in which
            # case the RestError would otherwise raise later (during
            # `build_conf_info` iteration) and bypass this except.
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
                # Return 200 OK with empty entries + a WARN message.
                # See module docstring for why we cannot re-raise here.
                try:
                    confInfo.addWarnMsg(INPUTS_UNAVAILABLE_MESSAGE)
                except Exception:
                    pass
                return []
            raise
        return result

    def _is_input_page_unavailable(self, err):
        """Return True only when the inputs page is unavailable.

        Covers the three endpoint shapes UCC uses for inputs:
          * `DataInputModel` -- modular-input scheme stripped at deploy
            time. The probe distinguishes "scheme registered" (don't
            gate) from "scheme missing or inconclusive" (gate).
          * `SingleModel` / `MultipleModel` backed by an inputs-shaped
            conf file (e.g. ``google_cloud_billing_inputs.conf``). These
            share the configuration-page code path, so gating is
            restricted to endpoints whose ``conf_name`` matches the
            inputs convention; pure settings/credentials endpoints stay
            untouched.

        The gate intentionally relies on explicit signals only -- the
        modular-input probe and the error shape -- because cloud-managed
        SH role detection via solnlib proved unreliable in production
        (mixed/missing roles producing false negatives).
        """
        if is_true(os.environ.get(_DISABLE_GUARD_ENV, "")):
            return False
        if not _looks_like_scheme_missing(err):
            return False
        endpoint = self.endpoint
        if isinstance(endpoint, DataInputModel):
            registered = _scheme_registered(
                self.getSessionKey(),
                endpoint.app,
                endpoint.input_type,
            )
            # Treat None (inconclusive) the same as False so the page
            # never falls back to "Something Went Wrong" on a flaky probe.
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
