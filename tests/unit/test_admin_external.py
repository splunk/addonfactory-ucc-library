import json
from collections import namedtuple
from io import StringIO

import pytest

from splunktaucclib.rest_handler import admin_external
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
from splunktaucclib.rest_handler.endpoint import RestModel, SingleModel, MultipleModel

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

        if path.startswith("configs/conf-!TA_config"):
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
        assert client_mock.get.call_count == 12
        assert client_mock.get.paths == [
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-!TA_config/default",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-!TA_config/default",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-!TA_config/default",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
        ]
    else:
        assert client_mock.get.call_count == 9
        assert client_mock.get.paths == [
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-!TA_config/default",
            "configs/conf-demo_reload",
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-!TA_config/default",
            "configs/conf-demo_reload",
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-!TA_config/default",
            "configs/conf-demo_reload",
        ]


@pytest.mark.parametrize("override", [True, False])
@pytest.mark.parametrize("override_location", ["default", "config:demo_reload"])
def test_handle_single_model_reload_override(
    admin, client_mock, monkeypatch, override, override_location
):
    def _get(path, *args, **kwargs):
        _get.call_count += 1
        _get.paths.append(path)

        status = 200
        value = {"key": "value"}
        name = "test"

        if path == f"configs/conf-!TA_config/{override_location}":
            value = {"need_reload": override}
            name = override_location
        elif path.startswith("configs/conf-!TA_config"):
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

    if override and override_location == "default":
        assert client_mock.get.call_count == 8
        assert client_mock.get.paths == [
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-!TA_config/default",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-!TA_config/default",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
        ]

    if not override and override_location == "default":
        assert client_mock.get.call_count == 6
        assert client_mock.get.paths == [
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-!TA_config/default",
            "configs/conf-demo_reload",
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-!TA_config/default",
            "configs/conf-demo_reload",
        ]

    if override and override_location != "default":
        assert client_mock.get.call_count == 6
        assert client_mock.get.paths == [
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
        ]

    if not override and override_location != "default":
        assert client_mock.get.call_count == 4
        assert client_mock.get.paths == [
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-demo_reload",
            "configs/conf-!TA_config/config:demo_reload",
            "configs/conf-demo_reload",
        ]
