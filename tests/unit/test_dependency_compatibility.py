"""Compatibility checks for the supported urllib3 dependency range."""

from packaging.version import Version

import requests
import urllib3

from splunktaucclib.alert_actions_base import ModularAlertBase
from splunktaucclib.rest_handler.handler import RestHandler


def test_supported_urllib3_runtime_and_ucc_imports():
    """The UCC runtime must load with either supported urllib3 major version."""
    version = Version(urllib3.__version__)

    assert version >= Version("1.26.19")
    assert version < Version("3")
    assert requests.__version__
    assert RestHandler
    assert ModularAlertBase
