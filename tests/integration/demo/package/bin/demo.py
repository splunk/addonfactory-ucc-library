import sys

import import_declare_test
from splunklib import modularinput as smi


class Input(smi.Script):
    def __init__(self):
        super().__init__()

    def get_scheme(self):
        scheme = smi.Scheme("demo")
        scheme.description = "demo input"
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False
        scheme.add_argument(
            smi.Argument(
                "name", title="Name", description="Name", required_on_create=True
            )
        )
        return scheme

    def validate_input(self, definition):
        return

    def stream_events(self, inputs: smi.InputDefinition, event_writer: smi.EventWriter):
        event = smi.Event(
            data="test data",
            sourcetype="test-sourcetype",
        )
        event_writer.write_event(event)


if __name__ == "__main__":
    exit_code = Input().run(sys.argv)
    sys.exit(exit_code)
