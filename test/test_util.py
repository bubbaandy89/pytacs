import logging

from pytacs.util import configure_structlog, get_log_level_from_string


def test_get_log_level_from_string():
    assert get_log_level_from_string("debug") == logging.DEBUG


def test_configure_structlog():
    configure_structlog()
