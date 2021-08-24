# SPDX-FileCopyrightText: 2020 2020
#
# SPDX-License-Identifier: Apache-2.0

"""
Global Config Module
"""


import urllib.parse

from solnlib.splunk_rest_client import SplunkRestClient

from .configuration import Configs, Configuration, GlobalConfigError, Inputs, Settings
from .schema import GlobalConfigSchema

__all__ = [
    "GlobalConfigError",
    "GlobalConfigSchema",
    "GlobalConfig",
    "Inputs",
    "Configs",
    "Settings",
]


class GlobalConfig:
    def __init__(self, splunkd_uri, session_key, schema):
        """
        Global Config.

        :param splunkd_uri:
        :param session_key:
        :param schema:
        :type schema: GlobalConfigSchema
        """
        self._splunkd_uri = splunkd_uri
        self._session_key = session_key
        self._schema = schema

        splunkd_info = urllib.parse.urlparse(self._splunkd_uri)
        self._client = SplunkRestClient(
            self._session_key,
            self._schema.product,
            scheme=splunkd_info.scheme,
            host=splunkd_info.hostname,
            port=splunkd_info.port,
        )
        self._configuration = Configuration(self._client, self._schema)
        self._inputs = Inputs(self._client, self._schema)
        self._configs = Configs(self._client, self._schema)
        self._settings = Settings(self._client, self._schema)

    @property
    def inputs(self):
        return self._inputs

    @property
    def configs(self):
        return self._configs

    @property
    def settings(self):
        return self._settings

    # add support for batch save of configuration payload
    def save(self, payload):
        return self._configuration.save(payload)
