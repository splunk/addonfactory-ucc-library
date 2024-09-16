#
# Copyright 2024 Splunk Inc.
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
from urllib import parse
from requests.auth import HTTPBasicAuth
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
        data={"name": "test12", "interval": "5"},
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
        "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnamet"
        "oolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnameto"
        "olongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoo"
        "longnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametool"
        "ongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolo"
        "ngnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolon"
        "gnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolong"
        "nametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongn"
        "ametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongna"
        "metoolongnametoolongnamet",
    ],
)
def test_basic_name_validation(value):
    expected_msg = """<msg type="ERROR">Unexpected error "&lt;class 'splunktaucclib.rest_handler.error.RestError'&gt;" 
from python handler: "REST Error [400]: Bad Request -- (\'"default", ".", "..", string started with "_" 
and string including any one of ["*", "\\\\", "[", "]", "(", ")", "?", ":"] are reserved value which cannot be used 
for field Name\',)". See splunkd.log/python.log for more details.</msg>"""

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

    if value.startswith("toolongname"):
        assert (
            '<msg type="ERROR">Parameter "name" must be less than 1024'.replace(
                "\n", ""
            )
            in response.text
        )
    else:
        assert expected_msg.replace("\n", "") in response.text
        assert response.status_code == 500


@pytest.mark.parametrize(
    "value",
    [
        "ftestname",
        "toolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnamet"
        "oolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnametoolongnameto"
    ],
)
def test_custom_name_validation(value):
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

    if value.startswith("toolongname"):
        assert ('String length should be between 1 and 100' in response.text)
    else:
        assert expected_msg.replace("\n", "") in response.text
        assert response.status_code == 500
