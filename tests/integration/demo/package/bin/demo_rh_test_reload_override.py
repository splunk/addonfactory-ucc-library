import import_declare_test

from splunktaucclib.rest_handler.endpoint import (
    RestModel,
    SingleModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler
import logging

util.remove_http_proxy_env_vars()


special_fields = []
fields_logging = []
model = RestModel(fields_logging, name=None, special_fields=special_fields)

endpoint = SingleModel(
    "demo_test_reload_override",
    model=model,
)


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=AdminExternalHandler,
    )
