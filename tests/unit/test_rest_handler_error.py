import pytest

from splunktaucclib.rest_handler import error


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
