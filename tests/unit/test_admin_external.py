import json
from collections import namedtuple
from io import StringIO
from unittest.mock import MagicMock

import pytest

from splunktaucclib.rest_handler import admin_external
from splunktaucclib.rest_handler.admin_external import (
    INPUTS_UNAVAILABLE_MESSAGE,
    AdminExternalHandler,
)
from splunktaucclib.rest_handler.credentials import RestCredentials
from splunktaucclib.rest_handler.endpoint import (
    DataInputModel,
    MultipleModel,
    RestModel,
    SingleModel,
)
from splunktaucclib.rest_handler.endpoint.field import RestField
from splunktaucclib.rest_handler.error import RestError

Response = namedtuple("Response", ["body", "status"])


def eai_response(value, status, name="test"):
    return Response(
        body=StringIO(
            json.dumps({"entry": [{"content": value, "name": name, "acl": "acl"}]})
        ),
        status=status,
    )


@pytest.mark.parametrize("need_reload", [True, False])
@pytest.mark.parametrize("cls", [SingleModel, MultipleModel])
def test_handle_single_model_reload(admin, client_mock, need_reload, cls, monkeypatch):
    def _get(path, *args, **kwargs):
        _get.call_count += 1
        _get.paths.append(path)

        status = 200

        if path.startswith("configs/conf-_TA_config"):
            status = 404

        return eai_response({"key": "value"}, status)

    _get.call_count = 0
    _get.paths = []

    monkeypatch.setattr(client_mock, "get", _get)

    model = RestModel([], name=None, special_fields=[])

    if cls is MultipleModel:
        model = [model, RestModel([], name="test", special_fields=[])]

    endpoint = cls(
        "demo_reload",
        model,
        app="fake_app",
        need_reload=need_reload,
    )

    admin_external.handle(
        endpoint,
        handler=AdminExternalHandler,
    )

    assert admin.init.call_count == 1

    handler: AdminExternalHandler = admin.init.call_args[0][0]

    for _ in range(3):
        handler.get()

    if need_reload:
        assert client_mock.get.call_count == 9
        assert client_mock.get.paths == [
            "configs/conf-_TA_config/config",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
            "configs/conf-_TA_config/config",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
            "configs/conf-_TA_config/config",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
        ]
    else:
        assert client_mock.get.call_count == 6
        assert client_mock.get.paths == [
            "configs/conf-_TA_config/config",
            "configs/conf-demo_reload",
            "configs/conf-_TA_config/config",
            "configs/conf-demo_reload",
            "configs/conf-_TA_config/config",
            "configs/conf-demo_reload",
        ]


@pytest.mark.parametrize("override", [True, False])
def test_handle_single_model_reload_override(admin, client_mock, monkeypatch, override):
    def _get(path, *args, **kwargs):
        _get.call_count += 1
        _get.paths.append(path)

        status = 200
        value = {"key": "value"}
        name = "test"

        if path == f"configs/conf-_TA_config/config":
            value = {"need_reload": override}
            name = "config"
        elif path.startswith("configs/conf-_TA_config"):
            status = 404

        return eai_response(value, status, name)

    _get.call_count = 0
    _get.paths = []

    monkeypatch.setattr(client_mock, "get", _get)

    model = RestModel([], name=None, special_fields=[])

    endpoint = SingleModel(
        "demo_reload",
        model,
        app="fake_app",
        need_reload=True,
    )

    admin_external.handle(
        endpoint,
        handler=AdminExternalHandler,
    )

    assert admin.init.call_count == 1

    handler: AdminExternalHandler = admin.init.call_args[0][0]

    for _ in range(2):
        handler.get()

    if override:
        assert client_mock.get.call_count == 6
        assert client_mock.get.paths == [
            "configs/conf-_TA_config/config",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
            "configs/conf-_TA_config/config",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
        ]

    if not override:
        assert client_mock.get.call_count == 4
        assert client_mock.get.paths == [
            "configs/conf-_TA_config/config",
            "configs/conf-demo_reload",
            "configs/conf-_TA_config/config",
            "configs/conf-demo_reload",
        ]


def test_handle_encryption_placeholder(admin, client_mock, monkeypatch):
    class CredentialsManager:
        def get_password(self, user):
            return json.dumps(
                {
                    "password1": "decrypted_password1",
                    "password2": "decrypted_password2",
                    "password3": "decrypted_password3",
                },
            )

        def set_password(self, user, password):
            self.password = password

    credentials_manager = CredentialsManager()

    monkeypatch.setattr(
        RestCredentials, "_get_manager", lambda self, context: credentials_manager
    )

    def _get(path, *args, **kwargs):
        _get.call_count += 1
        _get.paths.append(path)

        if "secret_name" not in path:
            status = 404
            return eai_response({}, status)

        status = 200
        return eai_response(
            {
                "password1": "******",
                "password2": "********",
                "password3": "***",
            },
            status,
        )

    _get.call_count = 0
    _get.paths = []

    monkeypatch.setattr(client_mock, "get", _get)

    fields = [
        RestField(
            "password1", required=True, encrypted=True, default=None, validator=None
        ),
        RestField(
            "password2", required=True, encrypted=True, default=None, validator=None
        ),
        RestField(
            "password3", required=True, encrypted=True, default=None, validator=None
        ),
    ]

    model = RestModel(fields, name=None, special_fields=[])

    endpoint = SingleModel(
        "demo",
        model,
        app="fake_app",
    )

    admin_external.handle(
        endpoint,
        handler=AdminExternalHandler,
    )

    assert admin.init.call_count == 1

    handler: AdminExternalHandler = admin.init.call_args[0][0]

    conf_info = MagicMock()
    handler.get("secret_name", caller_args={"--cred--": [True]}, conf_info=conf_info)

    # Password 3 gets overwritten with placeholder as it's just 3 asterisks
    assert json.loads(credentials_manager.password) == {
        "password1": "decrypted_password1",
        "password2": "decrypted_password2",
        "password3": "***",
    }

    returned_values = {}

    # Translate mocked confInfo to dict for easier assertion
    for call in conf_info["secret_name"].__setitem__.call_args_list:
        key, value = call[0]
        returned_values[key] = value

    assert returned_values == {
        "password1": "decrypted_password1",
        "password2": "decrypted_password2",
        "password3": "***",
    }


# ---------------------------------------------------------------------------
# Search-head input-page guard
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_guard_cache():
    admin_external._scheme_registered_cache.clear()
    yield
    admin_external._scheme_registered_cache.clear()


def _install_raising_handler(monkeypatch, error):
    def _raising(*args, **kwargs):
        raise error

    monkeypatch.setattr(
        "splunktaucclib.rest_handler.handler.RestHandler.all", _raising
    )
    monkeypatch.setattr(
        "splunktaucclib.rest_handler.handler.RestHandler.get", _raising
    )


def _make_input_handler(admin, monkeypatch, error):
    """Wire a DataInputModel handler whose backend raises `error`."""
    model = RestModel([], name=None, special_fields=[])
    endpoint = DataInputModel("demo_input", model, app="fake_app")
    _install_raising_handler(monkeypatch, error)
    admin_external.handle(endpoint, handler=AdminExternalHandler)
    return admin.init.call_args[0][0]


def test_input_page_with_missing_scheme_returns_empty_with_warning(
    admin, monkeypatch
):
    """DataInputModel + probe says 'scheme missing' -> [] + WARN message."""
    monkeypatch.setattr(
        admin_external, "_scheme_registered", lambda _k, _a, _t: False
    )

    handler = _make_input_handler(
        admin, monkeypatch, RestError(404, "Not Found")
    )
    conf_info = MagicMock()
    assert handler.get(conf_info=conf_info) is None
    conf_info.addWarnMsg.assert_called_once_with(INPUTS_UNAVAILABLE_MESSAGE)


def test_input_page_with_inconclusive_probe_returns_empty_with_warning(
    admin, monkeypatch
):
    """Inconclusive probe (None) is treated as 'missing' so the UI never breaks."""
    monkeypatch.setattr(
        admin_external, "_scheme_registered", lambda _k, _a, _t: None
    )

    handler = _make_input_handler(
        admin, monkeypatch, RestError(500, "boom")
    )
    conf_info = MagicMock()
    assert handler.get(conf_info=conf_info) is None
    conf_info.addWarnMsg.assert_called_once_with(INPUTS_UNAVAILABLE_MESSAGE)


def test_input_page_when_scheme_is_registered_preserves_original_error(
    admin, monkeypatch
):
    """When splunkd confirms the scheme exists, original error must bubble."""
    monkeypatch.setattr(
        admin_external, "_scheme_registered", lambda _k, _a, _t: True
    )

    handler = _make_input_handler(
        admin, monkeypatch, RestError(500, "Internal Server Error")
    )

    with pytest.raises(RestError) as exc_info:
        handler.get()
    assert exc_info.value.status == 500


def test_per_entity_not_found_is_not_masked(admin, monkeypatch):
    """`does not exist` 404 is a legitimate per-entity error -- must bubble."""
    monkeypatch.setattr(
        admin_external, "_scheme_registered", lambda _k, _a, _t: False
    )

    handler = _make_input_handler(
        admin, monkeypatch, RestError(404, "name=missing does not exist")
    )

    with pytest.raises(RestError):
        handler.get()


def test_single_model_inputs_conf_is_gated(admin, monkeypatch):
    """SingleModel with an inputs-shaped conf_name is gated on the same error."""
    model = RestModel([], name=None, special_fields=[])
    endpoint = SingleModel("billing_inputs", model, app="fake_app")
    _install_raising_handler(monkeypatch, RestError(404, "Not Found"))
    admin_external.handle(endpoint, handler=AdminExternalHandler)
    handler = admin.init.call_args[0][0]

    conf_info = MagicMock()
    assert handler.get(conf_info=conf_info) is None
    conf_info.addWarnMsg.assert_called_once_with(INPUTS_UNAVAILABLE_MESSAGE)


def test_single_model_settings_endpoint_preserves_original_error(
    admin, monkeypatch
):
    """SingleModel without 'input' in conf_name (settings/credentials) is NOT gated."""
    model = RestModel([], name=None, special_fields=[])
    endpoint = SingleModel("demo_settings", model, app="fake_app")
    _install_raising_handler(monkeypatch, RestError(500, "boom"))
    admin_external.handle(endpoint, handler=AdminExternalHandler)
    handler = admin.init.call_args[0][0]

    with pytest.raises(RestError):
        handler.get()


def test_env_kill_switch_disables_guard(admin, monkeypatch):
    """SPLUNKTAUCC_DISABLE_SH_INPUT_GUARD=1 keeps the original error path."""
    monkeypatch.setenv("SPLUNKTAUCC_DISABLE_SH_INPUT_GUARD", "1")
    monkeypatch.setattr(
        admin_external, "_scheme_registered", lambda _k, _a, _t: False
    )

    handler = _make_input_handler(
        admin, monkeypatch, RestError(404, "Not Found")
    )

    with pytest.raises(RestError):
        handler.get()


def test_generator_raising_resterror_is_caught(admin, monkeypatch):
    """RestError raised by a generator (not pre-materialized) is still caught.

    Without the `list(...)` materialization in handleList, the raise
    would happen later during iteration in build_conf_info and bypass
    the except clause -- the test guards against that regression.
    """
    monkeypatch.setattr(
        admin_external, "_scheme_registered", lambda _k, _a, _t: False
    )

    def _generator(*args, **kwargs):
        raise RestError(404, "Not Found")
        yield  # pragma: no cover - makes this a generator function

    model = RestModel([], name=None, special_fields=[])
    endpoint = DataInputModel("demo_input", model, app="fake_app")
    monkeypatch.setattr(
        "splunktaucclib.rest_handler.handler.RestHandler.all", _generator
    )
    monkeypatch.setattr(
        "splunktaucclib.rest_handler.handler.RestHandler.get", _generator
    )
    admin_external.handle(endpoint, handler=AdminExternalHandler)
    handler = admin.init.call_args[0][0]

    conf_info = MagicMock()
    assert handler.get(conf_info=conf_info) is None
    conf_info.addWarnMsg.assert_called_once_with(INPUTS_UNAVAILABLE_MESSAGE)
