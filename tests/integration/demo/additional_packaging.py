from pathlib import Path
from textwrap import dedent


def cleanup_output_files(output_path: str, ta_name: str) -> None:
    """Helper function used by UCC. It is here used to register a new handler not defined in the globalConfig."""
    web_conf = Path(output_path) / ta_name / "default" / "web.conf"
    restmap_conf = Path(output_path) / ta_name / "default" / "restmap.conf"

    assert web_conf.exists()
    assert restmap_conf.exists()

    web_conf.write_text(
        web_conf.read_text()
        + dedent(
            """
            [expose:demo_test_reload_override]
            pattern = demo_test_reload_override
            methods = POST, GET

            [expose:demo_test_reload_override_specified]
            pattern = demo_test_reload_override/*
            methods = POST, GET, DELETE
            """
        )
    )

    restmap_conf.write_text(
        restmap_conf.read_text().replace(
            "members =", "members = demo_test_reload_override,"
        )
        + dedent(
            """
            [admin_external:demo_test_reload_override]
            handlertype = python
            python.version = python3
            handlerfile = demo_rh_test_reload_override.py
            handleractions = create, edit, list, remove
            handlerpersistentmode = true
            """
        )
    )
