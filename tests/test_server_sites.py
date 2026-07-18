import json
import os

import pytest

import cryptofile
import server

KEY1 = "test-key1-0123456789abcdef"


def test_ensure_sites_file_creates_empty_default_on_first_boot(tmp_path):
    data = server.ensure_sites_file(str(tmp_path), KEY1)

    sites_path = os.path.join(tmp_path, "data", server.SITES_FILENAME)
    assert os.path.exists(sites_path)
    assert data == {"sites": {}}


def test_ensure_sites_file_writes_matching_plaintext_json_mirror(tmp_path):
    data = server.ensure_sites_file(str(tmp_path), KEY1)

    json_path = os.path.join(tmp_path, "data", server.SITES_PLAINTEXT_FILENAME)
    assert os.path.exists(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        plaintext_data = json.load(f)

    assert plaintext_data == data


def test_ensure_sites_file_persists_encrypted_with_key1(tmp_path):
    server.ensure_sites_file(str(tmp_path), KEY1)
    sites_path = os.path.join(tmp_path, "data", server.SITES_FILENAME)
    reloaded = cryptofile.load(sites_path, KEY1, server.SITES_FILE_PURPOSE)
    assert reloaded == {"sites": {}}


def test_ensure_sites_file_does_not_overwrite_existing_data(tmp_path):
    sites_path = os.path.join(tmp_path, "data", server.SITES_FILENAME)
    custom_data = {"sites": {"hameenlinna": {"description": "main office"}}}
    cryptofile.save(sites_path, KEY1, server.SITES_FILE_PURPOSE, custom_data)

    result = server.ensure_sites_file(str(tmp_path), KEY1)

    assert result == custom_data


def test_ensure_sites_file_raises_if_existing_file_undecryptable(tmp_path):
    sites_path = os.path.join(tmp_path, "data", server.SITES_FILENAME)
    cryptofile.save(sites_path, "a-different-key1", server.SITES_FILE_PURPOSE, {"sites": {}})

    with pytest.raises(cryptofile.InvalidCryptoFileError):
        server.ensure_sites_file(str(tmp_path), KEY1)
