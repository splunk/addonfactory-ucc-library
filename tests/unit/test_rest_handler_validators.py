#
# Copyright 2026 Splunk Inc.
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

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from splunktaucclib.rest_handler.endpoint.validator import IndexName

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(is_valid: bool, reason: str = "") -> MagicMock:
    """Build a fake splunklib response for the _validateName endpoint."""
    content = {"is_valid": "true" if is_valid else "false", "name": "test"}
    if not is_valid:
        content["reason"] = reason
    body = json.dumps({"entry": [{"content": content}]}).encode()
    response = MagicMock()
    response.body.read.return_value = body
    return response


def _http_error(status: int, body: bytes = b"<error/>") -> Exception:
    """Build a fake splunklib HTTPError with the given status code."""
    from splunklib import binding

    response = MagicMock()
    response.status = status
    response.reason = "reason"
    response.body.read.return_value = body
    err = binding.HTTPError(response, body)
    err.status = status
    return err


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def patch_env(monkeypatch):
    monkeypatch.setitem(os.environ, "SPLUNKD_URI", "https://localhost:8089")


@pytest.fixture
def validator():
    return IndexName()


@pytest.fixture
def mock_ucclog(monkeypatch):
    from splunktaucclib.common import log as ucclog

    mock_logger = MagicMock()
    monkeypatch.setattr(ucclog, "logger", mock_logger)
    return mock_logger


# ---------------------------------------------------------------------------
# validate_fallback — local rules
# ---------------------------------------------------------------------------


class TestValidateFallback:
    @pytest.mark.parametrize(
        "name",
        [
            "main",
            "index42",
            "my-index_01",
            "MAIN",  # uppercase allowed per CharacterClass::ALPHA_NUM_UNDER_DASH
            "My-Index",  # mixed case
            "a" * 2048,  # exactly at max length
            "federated:my_dataset",  # valid name with optional prefix
            "_internal",
            "_audit",
            "_thefishbucket",
            "_telemetry",
            "_metrics",
            "_introspection",
            "_configtracker",
            "_dsphonehome",
            "_dsappevent",
            "_dsclient",
            "_cmc_summary",
            "_metrics_rollup",
            "_dm_summary",
            "_dsevent_index_summary",
            "help",
            "history",
            "sample",
            "splunklogger",
            "summary",
            "~.federated.my_dataset",  # valid MDL dataset name
            "~.federated." + "x" * 1023,  # dataset name 1023 chars — ok (< 1024)
            "_INTERNAL",  # uppercase — src_lower matches _internal in allowed set
            "_AUDIT",  # uppercase — src_lower matches _audit in allowed set
        ],
    )
    def test_valid_names(self, name):
        assert IndexName.validate_fallback(name) == ""

    @pytest.mark.parametrize(
        "name,reason_contains",
        [
            ("a" * 2049, "too long"),
            ("-bad", "cannot start with"),
            ("_custom", "cannot start with"),
            ("bad name!", "alphanumeric"),
            ("Bad Name", "alphanumeric"),  # space not in valid char set
            ("~.federated.", "required"),  # empty inner name after MDL prefix strip
            ("~.my_index", "alphanumeric"),  # ~ not in valid char set
            ("())())))))((", "alphanumeric"),
            ("kvstore", "kvstore"),
            ("KVSTORE", "kvstore"),  # case-insensitive reserved word check
            ("federated:KVSTORE", "kvstore"),  # case-insensitive after prefix strip
            ("federated:-bad", "cannot start with"),  # hyphen after prefix strip
            ("", "empty"),
            ("federated:", "empty"),  # empty name after prefix strip
            ("~.federated.my.dataset", "cannot contain"),  # dot in dataset name
            ("~.federated.default", "default"),  # reserved dataset name
            (
                "~.federated.DEFAULT",
                "default",
            ),  # reserved dataset name — case-insensitive
            ("~.federated.Default", "default"),  # reserved dataset name — mixed case
            ("~.federated." + "x" * 1024, "1024"),  # dataset name >= 1024 chars
        ],
    )
    def test_invalid_names(self, name, reason_contains):
        reason = IndexName.validate_fallback(name)
        assert reason != ""
        assert reason_contains in reason


# ---------------------------------------------------------------------------
# _get_session_key — reads __main__.___sessionKey
# ---------------------------------------------------------------------------


class TestGetSessionKey:
    def test_returns_session_key_when_set(self, monkeypatch):
        import __main__

        monkeypatch.setattr(__main__, "___sessionKey", "abc123", raising=False)
        assert IndexName._get_session_key() == "abc123"

    def test_returns_none_when_attribute_absent(self, monkeypatch):
        import __main__

        monkeypatch.delattr(__main__, "___sessionKey", raising=False)
        assert IndexName._get_session_key() is None


# ---------------------------------------------------------------------------
# _get_splunkd_info — env var vs solnlib fallback
# ---------------------------------------------------------------------------


class TestGetSplunkdInfo:
    def test_uses_splunkd_uri_env_var(self, monkeypatch):
        monkeypatch.setitem(os.environ, "SPLUNKD_URI", "https://myhost:9089")
        info = IndexName._get_splunkd_info()
        assert info.hostname == "myhost"
        assert info.port == 9089
        assert info.scheme == "https"

    def test_falls_back_to_get_splunkd_uri_when_env_absent(self, monkeypatch):
        monkeypatch.delitem(os.environ, "SPLUNKD_URI", raising=False)
        monkeypatch.setattr(
            "solnlib.splunkenv.get_splunkd_uri",
            lambda: "https://fallback:8089",
        )
        info = IndexName._get_splunkd_info()
        assert info.hostname == "fallback"
        assert info.port == 8089


# ---------------------------------------------------------------------------
# _call_validate_endpoint — HTTP interaction
# ---------------------------------------------------------------------------


class TestCallValidateEndpoint:
    _SESSION_KEY = "session_key"
    _APP_NAME = "test_app"

    def _splunkd_info(self):
        import urllib.parse

        return urllib.parse.urlparse("https://localhost:8089")

    def _make_validator_with_client(self, monkeypatch, client):
        self._rest_client_cls = MagicMock(return_value=client)
        monkeypatch.setattr(
            "solnlib.splunk_rest_client.SplunkRestClient",
            self._rest_client_cls,
        )
        monkeypatch.setattr(
            "splunktaucclib.rest_handler.util.get_base_app_name",
            lambda: self._APP_NAME,
        )
        monkeypatch.setattr(
            IndexName, "_get_session_key", staticmethod(lambda: self._SESSION_KEY)
        )
        monkeypatch.setattr(
            IndexName,
            "_get_splunkd_info",
            staticmethod(lambda: self._splunkd_info()),
        )
        return IndexName()

    def test_valid_name_returns_true(self, monkeypatch):
        client = MagicMock()
        client.post.return_value = _make_response(True)
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("main")
        assert result is True
        assert error is None

    def test_post_called_with_correct_endpoint_and_body(self, monkeypatch):
        client = MagicMock()
        client.post.return_value = _make_response(True)
        v = self._make_validator_with_client(monkeypatch, client)
        v._call_validate_endpoint("main")
        client.post.assert_called_once_with(
            IndexName._ENDPOINT,
            output_mode="json",
            body={"index_name": "main"},
        )

    def test_splunk_rest_client_constructed_with_correct_args(self, monkeypatch):
        client = MagicMock()
        client.post.return_value = _make_response(True)
        v = self._make_validator_with_client(monkeypatch, client)
        splunkd_info = self._splunkd_info()
        v._call_validate_endpoint("main")
        self._rest_client_cls.assert_called_once_with(
            self._SESSION_KEY,
            self._APP_NAME,
            scheme=splunkd_info.scheme,
            host=splunkd_info.hostname,
            port=splunkd_info.port,
        )

    def test_invalid_name_returns_false_with_reason(self, monkeypatch):
        client = MagicMock()
        client.post.return_value = _make_response(
            False, "Name contains invalid characters"
        )
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("bad:name")
        assert result is False
        assert error == "Name contains invalid characters"

    def test_invalid_name_missing_reason_uses_default(self, monkeypatch):
        client = MagicMock()
        body = json.dumps(
            {"entry": [{"content": {"is_valid": "false", "name": "x"}}]}
        ).encode()
        resp = MagicMock()
        resp.body.read.return_value = body
        client.post.return_value = resp
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("x")
        assert result is False
        assert error == "Invalid index name"

    @pytest.mark.parametrize(
        "body",
        [
            b"not json at all",
            json.dumps({"entry": []}).encode(),
            json.dumps({"entry": [{}]}).encode(),
            json.dumps({}).encode(),
            json.dumps(
                {"entry": [{"content": None}]}
            ).encode(),  # content: null → TypeError
        ],
    )
    def test_malformed_response_returns_none_for_fallback(
        self, monkeypatch, body, mock_ucclog
    ):
        client = MagicMock()
        resp = MagicMock()
        resp.body.read.return_value = body
        client.post.return_value = resp
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("main")
        assert result is None
        assert error is None
        mock_ucclog.error.assert_called_once()
        assert "Unexpected response" in mock_ucclog.error.call_args[0][0]

    def test_404_returns_none_for_fallback(self, monkeypatch, mock_ucclog):
        client = MagicMock()
        client.post.side_effect = _http_error(404)
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("main")
        assert result is None
        assert error is None
        mock_ucclog.warning.assert_called_once()
        assert "404" in mock_ucclog.warning.call_args[0][0]

    def test_403_returns_false_with_permissions_message(self, monkeypatch, mock_ucclog):
        client = MagicMock()
        client.post.side_effect = _http_error(403)
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("main")
        assert result is False
        assert "permissions" in error.lower()
        mock_ucclog.warning.assert_called_once()
        assert "403" in mock_ucclog.warning.call_args[0][0]

    def test_500_returns_false_with_status_in_message(self, monkeypatch, mock_ucclog):
        client = MagicMock()
        client.post.side_effect = _http_error(500)
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("main")
        assert result is False
        assert "500" in error
        mock_ucclog.warning.assert_called_once()
        assert "500" in str(mock_ucclog.warning.call_args)

    def test_400_index_name_not_supported_returns_none_for_fallback(
        self, monkeypatch, mock_ucclog
    ):
        body = json.dumps(
            {
                "messages": [
                    {"type": "ERROR", "text": IndexName._MSG_INDEX_NAME_NOT_SUPPORTED}
                ]
            }
        ).encode()
        client = MagicMock()
        client.post.side_effect = _http_error(400, body)
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("main")
        assert result is None
        assert error is None
        mock_ucclog.warning.assert_called_once()
        assert "400" in mock_ucclog.warning.call_args[0][0]

    def test_400_empty_messages_list_returns_false_with_status(
        self, monkeypatch, mock_ucclog
    ):
        body = json.dumps({"messages": []}).encode()
        client = MagicMock()
        client.post.side_effect = _http_error(400, body)
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("main")
        assert result is False
        assert "400" in error

    def test_400_null_messages_returns_false_with_status(
        self, monkeypatch, mock_ucclog
    ):
        body = json.dumps({"messages": None}).encode()
        client = MagicMock()
        client.post.side_effect = _http_error(400, body)
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("main")
        assert result is False
        assert "400" in error

    def test_400_other_message_returns_false_with_status(
        self, monkeypatch, mock_ucclog
    ):
        body = json.dumps(
            {"messages": [{"type": "ERROR", "text": "Some other bad request error"}]}
        ).encode()
        client = MagicMock()
        client.post.side_effect = _http_error(400, body)
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("main")
        assert result is False
        assert "400" in error
        mock_ucclog.warning.assert_called_once()
        assert "400" in str(mock_ucclog.warning.call_args)

    def test_unexpected_exception_returns_false_with_message(
        self, monkeypatch, mock_ucclog
    ):
        client = MagicMock()
        client.post.side_effect = RuntimeError("connection refused")
        v = self._make_validator_with_client(monkeypatch, client)
        result, error = v._call_validate_endpoint("main")
        assert result is False
        assert "connection refused" in error
        mock_ucclog.error.assert_called_once()
        assert "connection refused" in str(mock_ucclog.error.call_args)

    def test_no_session_key_returns_none_for_fallback(self, monkeypatch, mock_ucclog):
        monkeypatch.setattr(IndexName, "_get_session_key", staticmethod(lambda: None))
        mock_splunkd = MagicMock()
        monkeypatch.setattr(IndexName, "_get_splunkd_info", staticmethod(mock_splunkd))
        result, error = IndexName()._call_validate_endpoint("main")
        assert result is None
        assert error is None
        mock_ucclog.error.assert_called_once()
        assert "session key" in mock_ucclog.error.call_args[0][0]

    def test_splunkd_info_not_called_when_no_session_key(self, monkeypatch):
        monkeypatch.setattr(IndexName, "_get_session_key", staticmethod(lambda: None))
        mock_splunkd = MagicMock()
        monkeypatch.setattr(IndexName, "_get_splunkd_info", staticmethod(mock_splunkd))
        IndexName()._call_validate_endpoint("main")
        mock_splunkd.assert_not_called()


# ---------------------------------------------------------------------------
# validate — full orchestration
# ---------------------------------------------------------------------------


class TestValidate:
    @pytest.fixture
    def patched_validator(self, monkeypatch):
        import urllib.parse

        monkeypatch.setattr(
            IndexName, "_get_session_key", staticmethod(lambda: "fake_key")
        )
        monkeypatch.setattr(
            IndexName,
            "_get_splunkd_info",
            staticmethod(lambda: urllib.parse.urlparse("https://localhost:8089")),
        )
        return IndexName()

    def test_no_session_key_falls_back_to_local_rules(self, monkeypatch):
        monkeypatch.setattr(IndexName, "_get_session_key", staticmethod(lambda: None))
        v = IndexName()
        assert v.validate("main", {}) is True
        assert v.validate("kvstore", {}) is False
        assert "kvstore" in v.msg

    def test_validate_endpoint_called_with_value(self, patched_validator, monkeypatch):
        mock_endpoint = MagicMock(return_value=(True, None))
        monkeypatch.setattr(patched_validator, "_call_validate_endpoint", mock_endpoint)
        patched_validator.validate("main", {})
        mock_endpoint.assert_called_once_with("main")

    def test_valid_name_via_endpoint(self, patched_validator, monkeypatch):
        monkeypatch.setattr(
            patched_validator,
            "_call_validate_endpoint",
            MagicMock(return_value=(True, None)),
        )
        assert patched_validator.validate("main", {}) is True

    def test_invalid_name_via_endpoint_sets_msg(self, patched_validator, monkeypatch):
        monkeypatch.setattr(
            patched_validator,
            "_call_validate_endpoint",
            MagicMock(return_value=(False, "Name is reserved")),
        )
        assert patched_validator.validate("kvstore", {}) is False
        assert patched_validator.msg == "Name is reserved"

    def test_fallback_called_when_endpoint_unavailable(
        self, patched_validator, monkeypatch
    ):
        monkeypatch.setattr(
            patched_validator,
            "_call_validate_endpoint",
            MagicMock(return_value=(None, None)),
        )
        mock_fallback = MagicMock(return_value="")
        monkeypatch.setattr(IndexName, "validate_fallback", staticmethod(mock_fallback))
        patched_validator.validate("main", {})
        mock_fallback.assert_called_once_with("main")

    def test_fallback_valid_when_endpoint_unavailable(
        self, patched_validator, monkeypatch
    ):
        monkeypatch.setattr(
            patched_validator,
            "_call_validate_endpoint",
            MagicMock(return_value=(None, None)),
        )
        assert patched_validator.validate("main", {}) is True

    @pytest.mark.parametrize(
        "name,reason_contains",
        [
            ("a" * 2049, "too long"),
            ("-bad", "cannot start with"),
            ("_custom", "cannot start with"),
            ("bad name!", "alphanumeric"),
            ("Bad Name", "alphanumeric"),
            ("~.federated.", "required"),
            ("~.my_index", "alphanumeric"),
            ("())())))))((", "alphanumeric"),
            ("kvstore", "kvstore"),
            ("KVSTORE", "kvstore"),
            ("federated:KVSTORE", "kvstore"),
            ("federated:-bad", "cannot start with"),
            ("", "empty"),
            ("federated:", "empty"),
            ("~.federated.my.dataset", "cannot contain"),
            ("~.federated.default", "default"),
            (
                "~.federated.DEFAULT",
                "default",
            ),  # reserved dataset name — case-insensitive
            ("~.federated." + "x" * 1024, "1024"),  # dataset name >= 1024 chars
        ],
    )
    def test_fallback_invalid_when_endpoint_unavailable(
        self, patched_validator, monkeypatch, name, reason_contains
    ):
        monkeypatch.setattr(
            patched_validator,
            "_call_validate_endpoint",
            MagicMock(return_value=(None, None)),
        )
        assert patched_validator.validate(name, {}) is False
        assert reason_contains in patched_validator.msg

    def test_endpoint_error_returns_false_with_msg(
        self, patched_validator, monkeypatch
    ):
        monkeypatch.setattr(
            patched_validator,
            "_call_validate_endpoint",
            MagicMock(return_value=(False, "HTTP 500")),
        )
        assert patched_validator.validate("main", {}) is False
        assert patched_validator.msg == "HTTP 500"
