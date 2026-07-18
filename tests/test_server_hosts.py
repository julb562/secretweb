import datetime
import json
import os
import socket

import pytest

import cryptofile
import server

KEY1 = "test-key1-0123456789abcdef"


def test_ensure_hosts_file_creates_default_on_first_boot(tmp_path):
    before = datetime.datetime.now(datetime.timezone.utc)
    data = server.ensure_hosts_file(str(tmp_path), KEY1, 59222)
    after = datetime.datetime.now(datetime.timezone.utc)

    hosts_path = os.path.join(tmp_path, "data", server.HOSTS_FILENAME)
    assert os.path.exists(hosts_path)

    own_name = socket.gethostname()
    own_record = data["hosts"][own_name]
    last_updated = own_record.pop("last_updated")
    assert own_record == {
        "address": "127.0.0.1",
        "all_addresses": ["127.0.0.1"],
        "port": 59222,
        "role": "server",
        "status": "local",
        "site": "",
        "online": "unknown",
    }
    assert own_record["address"] in own_record["all_addresses"]

    parsed = datetime.datetime.fromisoformat(last_updated)
    assert parsed.utcoffset() == datetime.timedelta(0)  # stored in UTC
    assert before <= parsed <= after


def test_ensure_hosts_file_writes_matching_plaintext_json_mirror(tmp_path):
    data = server.ensure_hosts_file(str(tmp_path), KEY1, 59222)

    json_path = os.path.join(tmp_path, "data", server.HOSTS_PLAINTEXT_FILENAME)
    assert os.path.exists(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        plaintext_data = json.load(f)

    assert plaintext_data == data


def test_ensure_hosts_file_persists_encrypted_with_key1(tmp_path):
    server.ensure_hosts_file(str(tmp_path), KEY1, 59222)
    hosts_path = os.path.join(tmp_path, "data", server.HOSTS_FILENAME)
    reloaded = cryptofile.load(hosts_path, KEY1, server.HOSTS_FILE_PURPOSE)
    own_name = socket.gethostname()
    assert reloaded["hosts"][own_name]["port"] == 59222


def test_ensure_hosts_file_does_not_overwrite_existing_data(tmp_path):
    hosts_path = os.path.join(tmp_path, "data", server.HOSTS_FILENAME)
    custom_data = {"hosts": {"some-other-host": {"address": "10.0.0.5", "port": 1234}}}
    cryptofile.save(hosts_path, KEY1, server.HOSTS_FILE_PURPOSE, custom_data)

    result = server.ensure_hosts_file(str(tmp_path), KEY1, 59222)

    assert result == custom_data


def test_ensure_hosts_file_raises_if_existing_file_undecryptable(tmp_path):
    hosts_path = os.path.join(tmp_path, "data", server.HOSTS_FILENAME)
    cryptofile.save(hosts_path, "a-different-key1", server.HOSTS_FILE_PURPOSE, {"hosts": {}})

    with pytest.raises(cryptofile.InvalidCryptoFileError):
        server.ensure_hosts_file(str(tmp_path), KEY1, 59222)
