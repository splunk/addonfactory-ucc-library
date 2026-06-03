import os
import sys
import types
from unittest.mock import MagicMock

import pytest

# Stub solnlib.log before any splunktaucclib module imports it, so that
# splunktaucclib.common.log can be imported outside a Splunk process.
_mock_logs_instance = MagicMock()
_mock_logs_instance.get_logger.return_value = MagicMock()
_solnlib_log_stub = types.ModuleType("solnlib.log")
_solnlib_log_stub.Logs = MagicMock(return_value=_mock_logs_instance)
sys.modules.setdefault("solnlib.log", _solnlib_log_stub)

from tests.unit.fake_module import mock_splunk_module


mock_splunk_module()


@pytest.fixture
def admin(monkeypatch) -> MagicMock:
    from splunktaucclib.rest_handler import admin_external

    new_admin = mock_splunk_module()
    monkeypatch.setattr(admin_external, "admin", new_admin)

    return new_admin


@pytest.fixture
def client_mock():
    return MagicMock()


@pytest.fixture(autouse=True)
def setup(monkeypatch, client_mock):
    from splunktaucclib.rest_handler import credentials
    from splunktaucclib.rest_handler import handler

    monkeypatch.setitem(os.environ, "SPLUNKD_URI", "https://localhost:1234")
    monkeypatch.setattr(credentials, "get_base_app_name", lambda: "splunk_ta_test")
    monkeypatch.setattr(
        handler, "SplunkRestClient", MagicMock(return_value=client_mock)
    )
