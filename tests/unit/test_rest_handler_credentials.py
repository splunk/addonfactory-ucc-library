import pytest

from splunktaucclib.rest_handler.credentials import RestCredentials


def test_current_placeholder_is_recognized():
    """The current 6-character placeholder should be recognized."""
    assert RestCredentials.is_placeholder("******") is True


def test_legacy_placeholder_is_recognized():
    """The legacy 8-character placeholder from older TAs should be recognized."""
    assert RestCredentials.is_placeholder("********") is True


def test_empty_string_is_not_placeholder():
    """Empty string should not be recognized as a placeholder."""
    assert RestCredentials.is_placeholder("") is False


def test_actual_password_is_not_placeholder():
    """Actual password values should not be recognized as placeholders."""
    assert RestCredentials.is_placeholder("my_secret_password") is False
    assert RestCredentials.is_placeholder("P@ssw0rd!") is False


def test_partial_asterisk_strings_are_not_placeholders():
    """Strings with fewer or more asterisks should not be placeholders."""
    assert RestCredentials.is_placeholder("*") is False
    assert RestCredentials.is_placeholder("**") is False
    assert RestCredentials.is_placeholder("***") is False
    assert RestCredentials.is_placeholder("****") is False
    assert RestCredentials.is_placeholder("*****") is False
    # 7 asterisks - between current (6) and legacy (8)
    assert RestCredentials.is_placeholder("*******") is False
    # 9 asterisks - more than legacy
    assert RestCredentials.is_placeholder("*********") is False


def test_mixed_asterisk_strings_are_not_placeholders():
    """Strings mixing asterisks with other characters should not be placeholders."""
    assert RestCredentials.is_placeholder("******a") is False
    assert RestCredentials.is_placeholder("a******") is False
    assert RestCredentials.is_placeholder("***a***") is False
    assert RestCredentials.is_placeholder("********b") is False


def test_placeholder_constants_match_method():
    """Verify the constants match what is_placeholder() accepts."""
    assert RestCredentials.is_placeholder(RestCredentials.PASSWORD) is True
    assert RestCredentials.is_placeholder(RestCredentials.LEGACY_PASSWORD) is True
