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

import requests

username = "admin"
password = "Chang3d!"
host = "localhost"
ui_port = 8000
management_port = 8089


def _get_session_key():
    response = requests.post(
        f"https://{host}:{management_port}/services/auth/login?output_mode=json",
        data=parse.urlencode({"username": username, "password": password}),
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
