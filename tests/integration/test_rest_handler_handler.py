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
from python handler: "REST Error [400]: Bad Request -- HTTP 400 Bad Request -- 
b'{"messages":[{"type":"ERROR","text":"Object id=demo://dashboard cannot be deleted in config=inputs."}]}'". 
See splunkd.log/python.log for more details.</msg>"""
    try:
        response = requests.delete(
            f"https://{host}:{management_port}/servicesNS/-/demo/demo_demo/dashboard",
            auth=HTTPBasicAuth(admin, admin_password),
            verify=False,
        )
        response_txt = response.text
        assert expected_msg.replace("\n", "") in response_txt
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 500


def test_403_api_call():
    expected_msg = """<msg type="ERROR">Unexpected error "&lt;class 'splunktaucclib.rest_handler.error.RestError'&gt;" 
from python handler: "REST Error [403]: Forbidden -- HTTP 403 Forbidden -- 
b'{"messages":[{"type":"ERROR","text":"You (user=user) do not have permission to perform this operation 
(requires capability: admin_all_objects)."}]}'". See splunkd.log/python.log for more details.</msg>"""
    try:
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
        response_txt = response.text
        assert expected_msg.replace("\n", "") in response_txt
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        assert e.response.status_code == 500
