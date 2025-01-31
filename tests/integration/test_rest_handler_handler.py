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
from datetime import datetime
from time import sleep
from typing import List, Any
from urllib import parse
from requests.auth import HTTPBasicAuth
from splunktaucclib.rest_handler.handler import BASIC_NAME_VALIDATORS
import requests
import os

import pytest

admin = os.getenv("SPLUNK_ADMIN")
admin_password = os.getenv("SPLUNK_ADMIN_PWD")
user = os.getenv("SPLUNK_USER")
user_password = os.getenv("SPLUNK_USER_PWD")
host = "localhost"
ui_port = 8000
management_port = 8089


def _get_session_key():
    response = requests.post(
        f"https://{host}:{management_port}/services/auth/login?output_mode=json",
        data=parse.urlencode({"username": admin, "password": admin_password}),
        verify=False,
    )
    content = response.json()
    return content["sessionKey"]


def _cookie_header():
    session_key = _get_session_key()
    return f"splunkd_8000={session_key}"


def test_inputs_api_call():
    try:
        response = requests.get(
            f"http://{host}:{ui_port}/en-GB/splunkd/__raw/servicesNS/nobody/demo/demo_demo?output_mode=json&count=-1",
            headers={
                "Cookie": _cookie_header(),
            },
        )
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        assert False, f"Exception {e}"


def test_400_api_call():
    expected_msg = """<msg type="ERROR">Unexpected error "&lt;class 'splunktaucclib.rest_handler.error.RestError'&gt;" 
from python handler: "REST Error [400]: Bad Request -- Object id=demo://test_input cannot be deleted in config=inputs.". 
See splunkd.log/python.log for more details.</msg>"""

    response = requests.delete(
        f"https://{host}:{management_port}/servicesNS/-/demo/demo_demo/test_input",
        auth=HTTPBasicAuth(admin, admin_password),
        verify=False,
    )
    assert expected_msg.replace("\n", "") in response.text
    assert response.status_code == 500


def test_403_api_call():
    expected_msg = """<msg type="ERROR">Unexpected error "&lt;class 'splunktaucclib.rest_handler.error.RestError'&gt;" 
from python handler: "REST Error [403]: Forbidden -- This operation is forbidden.". See splunkd.log/python.log for more details.</msg>"""

    response = requests.post(
        f"https://{host}:{management_port}/servicesNS/-/demo/demo_demo",
        data={"name": "atest12", "interval": "5"},
        headers={
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        auth=HTTPBasicAuth(user, user_password),
        verify=False,
    )
    assert expected_msg.replace("\n", "") in response.text
    assert response.status_code == 500


@pytest.mark.parametrize(
    "value",
    [
        "test[name",
        "test*name",
        "test\\name",
        "test]name",
        "test(name",
        "test)name",
        "test?name",
        "test:name",
    ],
)
def test_basic_name_validation_prohibited_char_and_names(value):
    prohibited_chars = BASIC_NAME_VALIDATORS["PROHIBITED_NAME_CHARACTERS"]
    prohibited_names = BASIC_NAME_VALIDATORS["PROHIBITED_NAMES"]
    expected_msg = (
        f'{prohibited_names}, string started with "_" and string including any one '
        f'of {prohibited_chars} are reserved value which cannot be used for field Name"'
    )

    response = requests.post(
        f"https://{host}:{management_port}/servicesNS/-/demo/demo_demo",
        data={"name": value, "interval": "44"},
        headers={
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        auth=HTTPBasicAuth(admin, admin_password),
        verify=False,
    )

    assert expected_msg.replace("\n", "") in response.text
    assert response.status_code == 500


def test_basic_name_validation_too_long_name():
    value = (
        (
            "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
            "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
            "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
            "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
            "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
            "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
            "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
            "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
            "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
            "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
            "toolongnametoolongnametoolongnamet"
        ),
    )

    response = requests.post(
        f"https://{host}:{management_port}/servicesNS/-/demo/demo_demo",
        data={"name": value, "interval": "44"},
        headers={
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        auth=HTTPBasicAuth(admin, admin_password),
        verify=False,
    )
    assert (
        '<msg type="ERROR">Parameter "name" must be less than 1024'.replace("\n", "")
        in response.text
    )


def test_custom_name_validation_invalid_name():
    value = "testname"
    expected_msg = """All of the following errors need to be fixed: ["Not matching the pattern: ^[a-dA-D]\\\\w*$"]"""

    response = requests.post(
        f"https://{host}:{management_port}/servicesNS/-/demo/demo_demo",
        data={"name": value, "interval": "44"},
        headers={
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        auth=HTTPBasicAuth(admin, admin_password),
        verify=False,
    )
    assert expected_msg.replace("\n", "") in response.text
    assert response.status_code == 500


def test_custom_name_validation_too_long_name():
    value = (
        "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
        "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongname"
        "toolongnametoolongnameto"
    )

    response = requests.post(
        f"https://{host}:{management_port}/servicesNS/-/demo/demo_demo",
        data={"name": value, "interval": "44"},
        headers={
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        auth=HTTPBasicAuth(admin, admin_password),
        verify=False,
    )
    assert "String length should be between 1 and 100" in response.text


def test_reload_override():
    def switch_reloads(enabled=None):
        try:
            requests.delete(
                f"https://{host}:{management_port}/servicesNS/nobody/demo/configs/conf-_TA_config/config?output_mode=json",
                headers={
                    "accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                auth=HTTPBasicAuth(admin, admin_password),
                verify=False,
            )
        except:
            pass

        if enabled is None:
            return

        response = requests.post(
            f"https://{host}:{management_port}/servicesNS/nobody/demo/configs/conf-_TA_config?output_mode=json",
            data={
                "name": "config",
                "need_reload": "1" if enabled else "0",
            },
            headers={
                "accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            auth=HTTPBasicAuth(admin, admin_password),
            verify=False,
        )

        assert response.ok, response.json()

    def call():
        response = requests.get(
            f"https://{host}:{management_port}/servicesNS/-/demo/demo_test_reload_override?output_mode=json",
            headers={
                "accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            auth=HTTPBasicAuth(admin, admin_password),
            verify=False,
        )

        assert response.status_code == 200

    def search_uris(earliest, latest):
        result = search(
            "search index=_internal AND uri_path=*/demo/* AND NOT uri_path=*services/search* "
            "AND (uri_path=*demo_test_reload_override* OR uri_path=*TA_config*)",
            earliest,
            latest,
        )
        return [res["uri_path"] for res in result if "GET" in res["_raw"]]

    def assert_search(earliest, latest, expected):
        for i in range(50):
            if search_uris(earliest, latest) == expected:
                return True
            sleep(0.1)
        else:
            assert search_uris(earliest, latest) == expected

    # make sure nothing is set
    switch_reloads()

    earliest = int(datetime.now().timestamp())

    for _ in range(2):
        call()

    latest = int(datetime.now().timestamp()) + 1

    assert assert_search(
        earliest,
        latest,
        [
            "/servicesNS/nobody/demo/configs/conf-demo_test_reload_override",
            "/servicesNS/nobody/demo/configs/conf-demo_test_reload_override/_reload",
            "/servicesNS/nobody/demo/configs/conf-_TA_config/config",
            "/servicesNS/nobody/demo/configs/conf-_TA_config/config%3Ademo_test_reload_override",
            "/servicesNS/-/demo/demo_test_reload_override",
            "/servicesNS/nobody/demo/configs/conf-demo_test_reload_override",
            "/servicesNS/nobody/demo/configs/conf-demo_test_reload_override/_reload",
            "/servicesNS/nobody/demo/configs/conf-_TA_config/config",
            "/servicesNS/nobody/demo/configs/conf-_TA_config/config%3Ademo_test_reload_override",
            "/servicesNS/-/demo/demo_test_reload_override",
        ],
    )

    # disable reloads
    switch_reloads(False)

    earliest = int(datetime.now().timestamp())

    for _ in range(2):
        call()

    latest = int(datetime.now().timestamp()) + 1

    # same as above, but without the reloads
    assert assert_search(
        earliest,
        latest,
        [
            "/servicesNS/nobody/demo/configs/conf-demo_test_reload_override",
            "/servicesNS/nobody/demo/configs/conf-_TA_config/config",
            "/servicesNS/nobody/demo/configs/conf-_TA_config/config%3Ademo_test_reload_override",
            "/servicesNS/-/demo/demo_test_reload_override",
            "/servicesNS/nobody/demo/configs/conf-demo_test_reload_override",
            "/servicesNS/nobody/demo/configs/conf-_TA_config/config",
            "/servicesNS/nobody/demo/configs/conf-_TA_config/config%3Ademo_test_reload_override",
            "/servicesNS/-/demo/demo_test_reload_override",
        ],
    )


def search(query: str, earliest_time: int, latest_time: int) -> List[Any]:
    response = requests.post(
        f"https://{host}:{management_port}/servicesNS/admin/demo/search/jobs?output_mode=json",
        data={
            "search": query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "exec_mode": "oneshot",
            "enable_lookups": "0",
        },
        headers={
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        auth=HTTPBasicAuth(admin, admin_password),
        verify=False,
    )

    return response.json()["results"]
