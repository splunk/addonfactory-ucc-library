import json
from collections import namedtuple
from io import StringIO
from unittest.mock import MagicMock

import pytest

from splunktaucclib.rest_handler import admin_external
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
from splunktaucclib.rest_handler.credentials import RestCredentials
from splunktaucclib.rest_handler.error import RestError
from splunktaucclib.rest_handler.endpoint import RestModel, SingleModel, MultipleModel
from splunktaucclib.rest_handler.endpoint.field import RestField

Response = namedtuple("Response", ["body", "status"])


@pytest.mark.parametrize(
    "action,method",
    [
        ("ACTION_LIST", "handleList"),
        ("ACTION_CREATE", "handleCreate"),
        ("ACTION_EDIT", "handleEdit"),
        ("ACTION_REMOVE", "handleRemove"),
    ],
)
@pytest.mark.parametrize(
    "status,exception_name",
    [
        (400, "ArgValidationException"),
        (401, "PermissionsException"),
        (403, "PermissionsException"),
        (404, "NotFoundException"),
        (409, "AlreadyExistsException"),
        (503, "ServiceUnavailableException"),
    ],
)
def test_execute_reports_expected_rest_error(
    admin, action, method, status, exception_name
):
    class CustomHandler(AdminExternalHandler):
        pass

    custom_method = MagicMock(side_effect=RestError(status, "Request was rejected"))
    setattr(CustomHandler, method, custom_method)
    handler = CustomHandler.__new__(CustomHandler)
    handler.requestedAction = getattr(admin, action)
    conf_info = MagicMock()

    with pytest.raises(getattr(admin, exception_name)) as exc_info:
        handler.execute(conf_info)

    assert str(exc_info.value) == "Request was rejected"
    assert "RestError" not in str(exc_info.value)
    custom_method.assert_called_once_with(conf_info)


@pytest.mark.parametrize(
    "error", [RestError(500, "Internal failure"), ValueError("Bug")]
)
def test_execute_preserves_unexpected_error(admin, error):
    class CustomHandler(AdminExternalHandler):
        def handleList(self, confInfo):
            raise error

    handler = CustomHandler.__new__(CustomHandler)
    handler.requestedAction = admin.ACTION_LIST

    with pytest.raises(type(error)) as exc_info:
        handler.execute(MagicMock())

    assert exc_info.value is error


def test_execute_preserves_successful_response(admin):
    class CustomHandler(AdminExternalHandler):
        def handleList(self, confInfo):
            confInfo["entry"] = {"value": "unchanged"}

    handler = CustomHandler.__new__(CustomHandler)
    handler.requestedAction = admin.ACTION_LIST
    conf_info = {}

    handler.execute(conf_info)

    assert conf_info == {"entry": {"value": "unchanged"}}


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
