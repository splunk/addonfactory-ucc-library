import json
from collections import namedtuple
from io import StringIO
from unittest.mock import MagicMock

import pytest

from splunktaucclib.rest_handler import admin_external
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
from splunktaucclib.rest_handler.credentials import RestCredentials
from splunktaucclib.rest_handler.endpoint import RestModel, SingleModel, MultipleModel
from splunktaucclib.rest_handler.endpoint.field import RestField

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
