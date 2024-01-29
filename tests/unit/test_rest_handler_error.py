import pytest

from splunktaucclib.rest_handler import error, handler
from splunklib import binding
from splunklib.data import record


def make_response_record(body, status=200):
    class _MocBufReader:
        def __init__(self, buf):
            if isinstance(buf, str):
                self._buf = buf.encode("utf-8")
            else:
                self._buf = buf

        def read(self, size=None):
            return self._buf

    return record(
        {
            "body": binding.ResponseReader(_MocBufReader(body)),
            "status": status,
            "reason": "",
            "headers": None,
        }
    )


@pytest.mark.parametrize(
    "status_code,message,expected_message",
    [
        (999, "message", "REST Error [999]: Unknown Error -- message"),
        (400, "message", "REST Error [400]: Bad Request -- message"),
        (401, "message", "REST Error [401]: Unauthorized -- message"),
        (402, "message", "REST Error [402]: Payment Required -- message"),
        (403, "message", "REST Error [403]: Forbidden -- message"),
        (404, "message", "REST Error [404]: Not Found -- message"),
        (405, "message", "REST Error [405]: Method Not Allowed -- message"),
        (406, "message", "REST Error [406]: Not Acceptable -- message"),
        (407, "message", "REST Error [407]: Proxy Authentication Required -- message"),
        (408, "message", "REST Error [408]: Request Timeout -- message"),
        (409, "message", "REST Error [409]: Conflict -- message"),
        (411, "message", "REST Error [411]: Length Required -- message"),
        (500, "message", "REST Error [500]: Internal Server Error -- message"),
        (503, "message", "REST Error [503]: Service Unavailable -- message"),
    ],
)
def test_rest_error(status_code, message, expected_message):
    with pytest.raises(Exception) as exc_info:
        raise error.RestError(status_code, "message")
    assert str(exc_info.value) == expected_message


def test_parse_err_msg_xml_forbidden():
    original_err_msg = """<?xml version="1.0" encoding="UTF-8"?>\n<response>\n <messages>\n \
<msg type="ERROR">You (user=user) do not have permission to perform this operation (requires capability: \
list_storage_passwords OR edit_storage_passwords OR admin_all_objects).</msg>\n </messages>\n</response>\n"""
    expected_err_msg = "This operation is forbidden."
    err = binding.HTTPError(make_response_record(original_err_msg, status=403))
    result = handler._parse_error_msg(err)
    assert result == expected_err_msg


def test_parse_err_msg_xml_forbidden_invalid():
    original_err_msg = "Error message - wrong format"
    err = binding.HTTPError(make_response_record(original_err_msg, status=403))
    result = handler._parse_error_msg(err)
    assert result == original_err_msg


def test_parse_err_msg_json_forbidden():
    original_err_msg = """{"messages":[{"type":"ERROR","text":"You (user=user) do not have permission to \
perform this operation (requires capability: admin_all_objects)."}]}"""
    expected_err_msg = "This operation is forbidden."
    err = binding.HTTPError(make_response_record(original_err_msg, status=403))
    result = handler._parse_error_msg(err)
    assert result == expected_err_msg


def test_parse_err_msg_json_forbidden_invalid():
    original_err_msg = """{"messages":{"type":"ERROR","text":"You (user=user) do not have permission to \
perform this operation (requires capability: admin_all_objects)."}}"""
    err = binding.HTTPError(make_response_record(original_err_msg, status=400))
    result = handler._parse_error_msg(err)
    assert result == original_err_msg


def test_parse_err_msg_json_bad_request():
    original_err_msg = """{"messages":[{"type":"ERROR","text":"\
Object id=demo://test_input cannot be deleted in config=inputs."}]}"""
    expected_err_msg = "Object id=demo://test_input cannot be deleted in config=inputs."
    err = binding.HTTPError(make_response_record(original_err_msg, status=400))
    result = handler._parse_error_msg(err)
    assert result == expected_err_msg
