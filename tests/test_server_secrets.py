import os

import pytest

import cryptofile
import server

KEY1 = "test-key1-0123456789abcdef"


def test_ensure_secrets_file_creates_empty_default_on_first_boot(tmp_path):
    data = server.ensure_secrets_file(str(tmp_path), KEY1)

    secrets_path = os.path.join(tmp_path, "data", server.SECRETS_FILENAME)
    assert os.path.exists(secrets_path)
    assert data == {"secrets": {}}


def test_ensure_secrets_file_never_writes_a_plaintext_mirror(tmp_path):
    server.ensure_secrets_file(str(tmp_path), KEY1)

    data_dir = os.path.join(tmp_path, "data")
    assert os.listdir(data_dir) == [server.SECRETS_FILENAME]


def test_ensure_secrets_file_persists_encrypted_with_key1(tmp_path):
    server.ensure_secrets_file(str(tmp_path), KEY1)
    secrets_path = os.path.join(tmp_path, "data", server.SECRETS_FILENAME)
    reloaded = cryptofile.load(secrets_path, KEY1, server.SECRETS_FILE_PURPOSE)
    assert reloaded == {"secrets": {}}


def test_ensure_secrets_file_does_not_overwrite_existing_data(tmp_path):
    secrets_path = os.path.join(tmp_path, "data", server.SECRETS_FILENAME)
    custom_data = {"secrets": {"my-secret": {"treshold": 3, "shares": 5}}}
    cryptofile.save(secrets_path, KEY1, server.SECRETS_FILE_PURPOSE, custom_data)

    result = server.ensure_secrets_file(str(tmp_path), KEY1)

    assert result == custom_data


def test_ensure_secrets_file_raises_if_existing_file_undecryptable(tmp_path):
    secrets_path = os.path.join(tmp_path, "data", server.SECRETS_FILENAME)
    cryptofile.save(secrets_path, "a-different-key1", server.SECRETS_FILE_PURPOSE, {"secrets": {}})

    with pytest.raises(cryptofile.InvalidCryptoFileError):
        server.ensure_secrets_file(str(tmp_path), KEY1)
