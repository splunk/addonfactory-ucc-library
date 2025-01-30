import json
from collections import namedtuple
from io import StringIO

import pytest

from splunktaucclib.rest_handler import admin_external
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
from splunktaucclib.rest_handler.endpoint import RestModel, SingleModel, MultipleModel

Response = namedtuple("Response", ["body"])


def eai_response(value):
    return Response(
        body=StringIO(
            json.dumps({"entry": [{"content": value, "name": "test", "acl": "acl"}]})
        )
    )


@pytest.mark.parametrize("need_reload", [True, False])
@pytest.mark.parametrize("cls", [SingleModel, MultipleModel])
def test_handle_single_model_reload(admin, client_mock, need_reload, cls):
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

    client_mock.get.return_value = eai_response({"key": "value"})

    handler: AdminExternalHandler = admin.init.call_args[0][0]

    for _ in range(3):
        client_mock.get.return_value = eai_response({"key": "value"})
        handler.get()

    if need_reload:
        assert client_mock.get.call_count == 6
        assert [i[0][0] for i in client_mock.get.call_args_list] == [
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
            "configs/conf-demo_reload/_reload",
            "configs/conf-demo_reload",
        ]
    else:
        assert client_mock.get.call_count == 3
        assert [i[0][0] for i in client_mock.get.call_args_list] == [
            "configs/conf-demo_reload",
            "configs/conf-demo_reload",
            "configs/conf-demo_reload",
        ]
