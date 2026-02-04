from unittest.mock import patch, MagicMock
import csv
from io import StringIO
import sys

import pytest

sys.modules["splunk"] = MagicMock()
sys.modules["splunk.rest"] = MagicMock()
sys.modules["splunk.clilib"] = MagicMock()
sys.modules["splunk.clilib.cli_common"] = MagicMock()
sys.modules["splunk.clilib.bundle_paths"] = MagicMock()
sys.modules["splunk.util"] = MagicMock()

from splunktaucclib.alert_actions_base import ModularAlertBase


@pytest.fixture
@patch("splunktaucclib.alert_actions_base.Setup_Util")
@patch("sys.stdin.read", return_value='{"key":"value"}')
@patch("splunktaucclib.alert_actions_base.log.Logs")
def alert(mock_log, mock_stdin_read, mock_setup_util):
    mock_logger = MagicMock()
    mock_log.return_value.get_logger.return_value = mock_logger
    mock_setup_util.return_value = MagicMock()

    alert = ModularAlertBase("ta_name", "alert_name")
    alert.results_file = "fake_results.gz"
    alert.update = MagicMock()
    alert.invoke = MagicMock()
    alert.log_error = MagicMock()

    return alert


@patch("gzip.open")
def test_prepare_meta_for_cam_success_no_rid(mock_gzip_open, alert):
    csv_content = "field1,field2\nvalue1,value2\nvalue3,value4\n"
    mock_gzip_open.return_value.__enter__.return_value = StringIO(csv_content)
    alert.prepare_meta_for_cam()
    expected_result = {"field1": "value1", "field2": "value2", "rid": "0"}
    alert.update.assert_called_once_with(expected_result)
    alert.invoke.assert_called_once()


@patch("gzip.open")
def test_prepare_meta_for_cam_success_empty_rid(mock_gzip_open, alert):
    csv_content = "field1,field2,rid\nvalue1,value2,\n"
    mock_gzip_open.return_value.__enter__.return_value = StringIO(csv_content)
    alert.prepare_meta_for_cam()
    expected_result = {"field1": "value1", "field2": "value2", "rid": "0"}
    alert.update.assert_called_once_with(expected_result)
    alert.invoke.assert_called_once()


@patch("gzip.open", side_effect=FileNotFoundError)
@patch("sys.exit")
def test_prepare_meta_for_cam_file_not_found(mock_exit, mock_gzip_open, alert):
    alert.prepare_meta_for_cam()
    alert.log_error.assert_called_once_with("File 'fake_results.gz' not found.")
    mock_exit.assert_called_once_with(2)


@patch("gzip.open", side_effect=OSError("Not a gzip file"))
@patch("sys.exit")
def test_prepare_meta_for_cam_bad_gzip(mock_exit, mock_gzip_open, alert):
    alert.prepare_meta_for_cam()
    alert.log_error.assert_called_once_with(
        "File 'fake_results.gz' is not a valid gzip file."
    )
    mock_exit.assert_called_once_with(2)


@patch("csv.DictReader", side_effect=csv.Error("bad csv"))
@patch("gzip.open")
@patch("sys.exit")
def test_prepare_meta_for_cam_csv_error(
    mock_exit, mock_gzip_open, mock_dictreader, alert
):
    mock_gzip_open.return_value.__enter__.return_value = MagicMock()

    alert.prepare_meta_for_cam()
    alert.log_error.assert_called_once()
    log_msg = alert.log_error.call_args[0][0]

    assert "CSV parsing error:" in log_msg
    assert "bad csv" in log_msg  # Confirm error message included
    mock_exit.assert_called_once_with(2)


@patch("gzip.open")
@patch("sys.exit")
def test_prepare_meta_for_cam_invalid_result_id(mock_exit, mock_gzip_open, alert):
    mock_gzip_open.return_value.__enter__.return_value = StringIO("field1\nvalue1\n")

    def raise_invalid_result_id(_):
        from splunktaucclib.cim_actions import InvalidResultID

        raise InvalidResultID("invalid id")

    alert.update.side_effect = raise_invalid_result_id

    alert.prepare_meta_for_cam()
    assert alert.log_error.call_args[0][0].startswith("Invalid result ID:")
    mock_exit.assert_called_once_with(2)


@patch("gzip.open")
@patch("sys.exit")
def test_prepare_meta_for_cam_unexpected_exception(mock_exit, mock_gzip_open, alert):
    mock_gzip_open.return_value.__enter__.return_value = StringIO("field1\nvalue1\n")
    alert.update.side_effect = Exception("unexpected error")

    alert.prepare_meta_for_cam()
    assert alert.log_error.call_args[0][0].startswith("An unexpected error occurred:")
    mock_exit.assert_called_once_with(2)
