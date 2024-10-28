import json
from pathlib import Path

import pytest

from pytacs.config import read_config_file
from pytacs.structures.models.configurations.configuration import Configuration

TEST_GOOD_CONFIG_FILE_CONTENTS_DICT = {
    "options": {"foreground": True, "syslog": True, "log_level": "DEBUG"},
    "modules": ["pyt_tacacs_server", "pyt_ldap_attributes"],
    "servers": [
        {
            "name": "tac1",
            "listening_address": "127.0.0.1",
            "listening_port": 49,
            "clients": [
                {
                    "name": "local_test",
                    "ip_address": "127.0.0.1",
                    "secret": "secret",
                }
            ],
        }
    ],
    "ldap": {
        "plugin_name": "ldap_server_fleet",
        "host_name": "",
        "host_ip": "192.168.100.60",
        "port": 389,
        "dn_format": "cn=%s,ou=people,dc=haqa,dc=net",
        "attributes": ["objectClass", "sn", "mail"],
        "values": ["inetOrgPerson", "", ""],
    },
    "mysql": {
        "plugin_name": "mysql_aa_db",
        "host_name": "",
        "host_ip": "192.168.100.60",
        "port": 3306,
        "database_name": "aaa_db",
        "table_name": "test_table",
        "database_user_name": "dbuser",
        "database_user_password": "XXXXXXXXXX",
        "user_column_name": "username",
        "password_column_name": "password",
        "group_membership_column_name": "memberOfGroups",
    },
}


@pytest.fixture
def temp_config_file(tmp_path):
    config_data = TEST_GOOD_CONFIG_FILE_CONTENTS_DICT
    config_file = tmp_path / "test_config.json"
    with open(config_file, "w") as f:
        json.dump(config_data, f)
    return config_file


def test_read_config_file_valid(temp_config_file):
    result = read_config_file(temp_config_file)
    assert isinstance(result, Configuration)


def test_read_config_file_nonexistent():
    with pytest.raises(FileNotFoundError):
        read_config_file(Path("nonexistent_config.json"))


def test_read_config_file_invalid_json(tmp_path):
    invalid_file = tmp_path / "invalid_config.json"
    with open(invalid_file, "w") as f:
        f.write("This is not valid JSON")

    with pytest.raises(json.JSONDecodeError):
        read_config_file(invalid_file)


def test_read_config_file_invalid_schema(tmp_path):
    invalid_schema_file = tmp_path / "invalid_schema_config.json"
    invalid_data = {"invalid_key": "This key is not in the Configuration model"}
    with open(invalid_schema_file, "w") as f:
        json.dump(invalid_data, f)

    with pytest.raises(ValueError):
        read_config_file(invalid_schema_file)


def test_read_config_file_empty(tmp_path):
    empty_file = tmp_path / "empty_config.json"
    empty_file.touch()

    with pytest.raises(json.JSONDecodeError):
        read_config_file(empty_file)
