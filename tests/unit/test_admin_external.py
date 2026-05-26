import json
from collections import namedtuple
from io import StringIO
from unittest.mock import MagicMock

import pytest

from splunktaucclib.rest_handler import admin_external
from splunktaucclib.rest_handler.admin_external import (
    AdminExternalHandler,
    INPUTS_UNAVAILABLE_CODE,
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


@pytest.fixture(autouse=True)
def _reset_guard_caches(monkeypatch):
    """Clean per-process caches and stub the scheme-registered probe so it
    never reaches splunkd unless a specific test overrides it."""
    admin_external._SEARCH_HEAD_ROLE_CACHE.clear()
    admin_external._SCHEME_REGISTERED_CACHE.clear()
    monkeypatch.setattr(
        admin_external, "_scheme_registered", lambda *args, **kwargs: None
    )
    yield
    admin_external._SEARCH_HEAD_ROLE_CACHE.clear()
    admin_external._SCHEME_REGISTERED_CACHE.clear()


def _data_input_endpoint():
    model = RestModel([], name=None, special_fields=[])
    return DataInputModel("demo_input", model, app="fake_app")


def _register(endpoint):
    admin_external.handle(endpoint, handler=AdminExternalHandler)


def _raise_on_client_get(client_mock, monkeypatch, err):
    """Make the underlying SplunkRestClient.get raise the given RestError."""

    def _raise(*args, **kwargs):
        raise err

    monkeypatch.setattr(client_mock, "get", _raise)


def _scheme_missing_error():
    """The 500/Unknown-handler shape splunkd returns on a SH when
    ``inputs.conf.spec`` is not deployed for the requested input type."""
    return RestError(500, "Unknown handler: demo_input")


def test_input_page_on_search_head_returns_friendly_error(
    admin, client_mock, monkeypatch
):
    _raise_on_client_get(client_mock, monkeypatch, _scheme_missing_error())
    monkeypatch.setattr(
        admin_external, "_is_search_head_instance", lambda *_: True
    )

    _register(_data_input_endpoint())
    handler: AdminExternalHandler = admin.init.call_args[0][0]

    with pytest.raises(RestError) as excinfo:
        handler.get()

    assert excinfo.value.status == 403
    message = excinfo.value.message
    # Customer-readable copy is the primary text, machine code is a stable
    # suffix the React UI can match without parsing JSON.
    assert message.startswith("Inputs cannot be configured on this instance.")
    assert "fake_app" in message
    assert f"[code={INPUTS_UNAVAILABLE_CODE}]" in message
    # str() representation (what splunkd serializes into messages[0].text)
    # remains human readable.
    assert "Inputs cannot be configured on this instance." in str(excinfo.value)


def test_input_page_on_idm_preserves_original_error(
    admin, client_mock, monkeypatch
):
    _raise_on_client_get(client_mock, monkeypatch, _scheme_missing_error())
    monkeypatch.setattr(
        admin_external, "_is_search_head_instance", lambda *_: False
    )

    _register(_data_input_endpoint())
    handler: AdminExternalHandler = admin.init.call_args[0][0]

    with pytest.raises(RestError) as excinfo:
        handler.get()

    # IDM behavior is unchanged: the original 500 surfaces as-is.
    assert excinfo.value.status == 500
    assert INPUTS_UNAVAILABLE_CODE not in excinfo.value.message
    assert "Unknown handler" in excinfo.value.message


def test_input_page_guard_disabled_via_env(
    admin, client_mock, monkeypatch
):
    _raise_on_client_get(client_mock, monkeypatch, _scheme_missing_error())
    monkeypatch.setattr(
        admin_external, "_is_search_head_instance", lambda *_: True
    )
    monkeypatch.setenv("SPLUNKTAUCC_DISABLE_SH_INPUT_GUARD", "1")

    _register(_data_input_endpoint())
    handler: AdminExternalHandler = admin.init.call_args[0][0]

    with pytest.raises(RestError) as excinfo:
        handler.get()

    # Escape hatch in effect: original error bubbles up.
    assert excinfo.value.status == 500


def test_non_input_endpoint_unaffected_on_search_head(
    admin, client_mock, monkeypatch
):
    _raise_on_client_get(client_mock, monkeypatch, _scheme_missing_error())
    monkeypatch.setattr(
        admin_external, "_is_search_head_instance", lambda *_: True
    )

    model = RestModel([], name=None, special_fields=[])
    endpoint = SingleModel("demo_conf", model, app="fake_app")
    _register(endpoint)
    handler: AdminExternalHandler = admin.init.call_args[0][0]

    with pytest.raises(RestError) as excinfo:
        handler.get()

    # SingleModel / MultipleModel paths are never input pages, so the guard
    # must not intercept their errors regardless of server role.
    assert excinfo.value.status == 500
    assert INPUTS_UNAVAILABLE_CODE not in excinfo.value.message


def test_input_page_legitimate_not_found_is_not_masked(
    admin, client_mock, monkeypatch
):
    """A real 'name does not exist' 404 (e.g. user requested a specific input
    that was deleted) must NOT be replaced with the Search-Head guard message
    even when the instance happens to be a Search Head — otherwise we'd hide
    legitimate API errors."""
    _raise_on_client_get(
        client_mock,
        monkeypatch,
        RestError(404, '"missing_input" does not exist'),
    )
    monkeypatch.setattr(
        admin_external, "_is_search_head_instance", lambda *_: True
    )

    _register(_data_input_endpoint())
    handler: AdminExternalHandler = admin.init.call_args[0][0]

    with pytest.raises(RestError) as excinfo:
        handler.get("missing_input")

    assert excinfo.value.status == 404
    assert INPUTS_UNAVAILABLE_CODE not in excinfo.value.message
    assert "does not exist" in excinfo.value.message


@pytest.mark.parametrize(
    "err",
    [
        RestError(500, ""),
        RestError(500, "In handler 'foo': Unable to load REST handler for context"),
        RestError(503, "service temporarily unavailable"),
        RestError(404, ""),
    ],
)
def test_input_page_guard_triggers_on_any_scheme_missing_shape(
    admin, client_mock, monkeypatch, err
):
    """Any 5xx (or non-legitimate 404) on a SH input page must surface the
    friendly message — splunkd error bodies vary across versions."""
    _raise_on_client_get(client_mock, monkeypatch, err)
    monkeypatch.setattr(
        admin_external, "_is_search_head_instance", lambda *_: True
    )

    _register(_data_input_endpoint())
    handler: AdminExternalHandler = admin.init.call_args[0][0]

    with pytest.raises(RestError) as excinfo:
        handler.get()

    assert excinfo.value.status == 403
    assert f"[code={INPUTS_UNAVAILABLE_CODE}]" in excinfo.value.message


def _make_fake_server_info(roles, *, sh=True, shc=False, counter=None):
    class FakeServerInfo:
        @classmethod
        def from_server_uri(cls, uri, key):
            if counter is not None:
                counter["n"] += 1
            return cls()

        def is_search_head(self):
            return sh

        def is_shc_member(self):
            return shc

        def to_dict(self):
            return {"server_roles": list(roles)}

    return FakeServerInfo


def _install_fake_solnlib(monkeypatch, server_info_cls):
    import sys

    fake_module = MagicMock()
    fake_module.ServerInfo = server_info_cls
    monkeypatch.setitem(sys.modules, "solnlib.server_info", fake_module)


def test_server_role_detection_is_cached(monkeypatch):
    counter = {"n": 0}
    _install_fake_solnlib(
        monkeypatch,
        _make_fake_server_info(["search_head"], counter=counter),
    )

    for _ in range(5):
        assert admin_external._is_search_head_instance(
            "https://localhost:8089", "key"
        )

    assert counter["n"] == 1


def test_server_role_detection_falls_back_on_error(monkeypatch):
    class BrokenServerInfo:
        @classmethod
        def from_server_uri(cls, uri, key):
            raise RuntimeError("network down")

    _install_fake_solnlib(monkeypatch, BrokenServerInfo)

    assert (
        admin_external._is_search_head_instance("https://localhost:8089", "key")
        is False
    )


def test_mixed_role_box_is_not_treated_as_search_head(monkeypatch):
    """An all-in-one dev box (search_head + indexer) hosts inputs locally
    and must NOT trigger the guard."""
    _install_fake_solnlib(
        monkeypatch,
        _make_fake_server_info(["search_head", "indexer"]),
    )

    assert (
        admin_external._is_search_head_instance("https://localhost:8089", "key")
        is False
    )


def test_pure_search_head_is_detected(monkeypatch):
    _install_fake_solnlib(
        monkeypatch,
        _make_fake_server_info(["search_head"]),
    )

    assert (
        admin_external._is_search_head_instance("https://localhost:8089", "key")
        is True
    )


@pytest.mark.parametrize(
    "roles",
    [
        ["search_head", "cluster_master"],
        ["search_head", "shc_deployer"],
        ["search_head", "license_master"],
        ["shc_member"],
    ],
)
def test_non_input_owning_search_head_variants_trigger_guard(monkeypatch, roles):
    """Cluster master, SHC deployer, and license master do not own inputs,
    so the guard must fire on them (same UX as a plain search head)."""
    sh = "search_head" in roles
    shc = "shc_member" in roles
    _install_fake_solnlib(
        monkeypatch,
        _make_fake_server_info(roles, sh=sh, shc=shc),
    )

    assert (
        admin_external._is_search_head_instance("https://localhost:8089", "key")
        is True
    )


def test_role_detection_does_not_cache_lookup_failure(monkeypatch):
    """A one-time solnlib/REST failure must NOT permanently disable the guard;
    the next call should retry."""
    state = {"raise": True}

    class FlakyServerInfo:
        @classmethod
        def from_server_uri(cls, uri, key):
            if state["raise"]:
                raise RuntimeError("transient")
            return cls()

        def is_search_head(self):
            return True

        def is_shc_member(self):
            return False

        def to_dict(self):
            return {"server_roles": ["search_head"]}

    _install_fake_solnlib(monkeypatch, FlakyServerInfo)

    assert (
        admin_external._is_search_head_instance("https://localhost:8089", "key")
        is False
    )
    assert "https://localhost:8089" not in admin_external._SEARCH_HEAD_ROLE_CACHE

    state["raise"] = False
    assert (
        admin_external._is_search_head_instance("https://localhost:8089", "key")
        is True
    )


def test_input_page_does_not_fire_when_scheme_is_registered(
    admin, client_mock, monkeypatch
):
    """A transient 500 on a SH that DOES have the scheme registered must
    bubble the original error — we should not mislead the user."""
    _raise_on_client_get(client_mock, monkeypatch, _scheme_missing_error())
    monkeypatch.setattr(
        admin_external, "_is_search_head_instance", lambda *_: True
    )
    monkeypatch.setattr(
        admin_external, "_scheme_registered", lambda *_, **__: True
    )

    _register(_data_input_endpoint())
    handler: AdminExternalHandler = admin.init.call_args[0][0]

    with pytest.raises(RestError) as excinfo:
        handler.get()

    assert excinfo.value.status == 500
    assert INPUTS_UNAVAILABLE_CODE not in excinfo.value.message


def test_input_page_fires_when_scheme_check_is_unknown(
    admin, client_mock, monkeypatch
):
    """When the scheme-registration check itself fails (None), the guard
    still fires — preserves the original bug fix on classic SH."""
    _raise_on_client_get(client_mock, monkeypatch, _scheme_missing_error())
    monkeypatch.setattr(
        admin_external, "_is_search_head_instance", lambda *_: True
    )
    monkeypatch.setattr(
        admin_external, "_scheme_registered", lambda *_, **__: None
    )

    _register(_data_input_endpoint())
    handler: AdminExternalHandler = admin.init.call_args[0][0]

    with pytest.raises(RestError) as excinfo:
        handler.get()

    assert excinfo.value.status == 403
    assert f"[code={INPUTS_UNAVAILABLE_CODE}]" in excinfo.value.message


def test_input_page_fires_when_scheme_is_verifiably_missing(
    admin, client_mock, monkeypatch
):
    _raise_on_client_get(client_mock, monkeypatch, _scheme_missing_error())
    monkeypatch.setattr(
        admin_external, "_is_search_head_instance", lambda *_: True
    )
    monkeypatch.setattr(
        admin_external, "_scheme_registered", lambda *_, **__: False
    )

    _register(_data_input_endpoint())
    handler: AdminExternalHandler = admin.init.call_args[0][0]

    with pytest.raises(RestError) as excinfo:
        handler.get()

    assert excinfo.value.status == 403
    assert f"[code={INPUTS_UNAVAILABLE_CODE}]" in excinfo.value.message
