import logging

from pytacs.util import get_log_level_from_string


def test_get_log_level_from_string():
    assert get_log_level_from_string("debug") == logging.DEBUG
