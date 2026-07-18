import json
import os

import pytest

import cryptofile

KEY1 = "test-key1-0123456789abcdef"
PURPOSE = "secretweb-hosts-v1"


def test_encrypt_decrypt_roundtrip():
    plaintext = b'{"hosts": {"a": {"role": "server"}}}'
    blob = cryptofile.encrypt(KEY1, PURPOSE, plaintext)
    assert cryptofile.decrypt(KEY1, PURPOSE, blob) == plaintext


def test_ciphertext_is_not_plaintext():
    plaintext = b"a" * 200  # long repeated run - easy to spot if it leaked through
    blob = cryptofile.encrypt(KEY1, PURPOSE, plaintext)
    assert plaintext not in blob


@pytest.mark.parametrize("data", [
    {},
    {"hosts": {}},
    {"hosts": {"host-a": {"address": "127.0.0.1", "port": 59222}}},
    {"unicode": "sähköposti \U0001F600"},
    {"nested": {"a": [1, 2, {"b": None, "c": True}]}},
])
def test_save_load_roundtrip(tmp_path, data):
    path = os.path.join(tmp_path, "data", "hosts.dta")
    cryptofile.save(path, KEY1, PURPOSE, data)
    assert cryptofile.load(path, KEY1, PURPOSE) == data


def test_save_creates_missing_parent_directory(tmp_path):
    path = os.path.join(tmp_path, "does", "not", "exist", "yet", "hosts.dta")
    cryptofile.save(path, KEY1, PURPOSE, {"a": 1})
    assert cryptofile.load(path, KEY1, PURPOSE) == {"a": 1}


def test_save_leaves_no_temp_files_behind(tmp_path):
    path = os.path.join(tmp_path, "hosts.dta")
    cryptofile.save(path, KEY1, PURPOSE, {"a": 1})
    assert os.listdir(tmp_path) == ["hosts.dta"]


def test_wrong_key_rejected(tmp_path):
    path = os.path.join(tmp_path, "hosts.dta")
    cryptofile.save(path, KEY1, PURPOSE, {"a": 1})
    with pytest.raises(cryptofile.InvalidCryptoFileError):
        cryptofile.load(path, "a-different-key", PURPOSE)


def test_wrong_purpose_rejected(tmp_path):
    path = os.path.join(tmp_path, "hosts.dta")
    cryptofile.save(path, KEY1, PURPOSE, {"a": 1})
    with pytest.raises(cryptofile.InvalidCryptoFileError):
        cryptofile.load(path, KEY1, "secretweb-shares-v1")


def test_tampered_ciphertext_rejected(tmp_path):
    path = os.path.join(tmp_path, "hosts.dta")
    cryptofile.save(path, KEY1, PURPOSE, {"a": 1})
    with open(path, "r+b") as f:
        f.seek(-1, os.SEEK_END)
        last_byte = f.read(1)
        f.seek(-1, os.SEEK_END)
        f.write(bytes([last_byte[0] ^ 0xFF]))
    with pytest.raises(cryptofile.InvalidCryptoFileError):
        cryptofile.load(path, KEY1, PURPOSE)


def test_swapping_ciphertext_between_purposes_rejected(tmp_path):
    """A file encrypted for one purpose must not decrypt under another,
    even with the same KEY1 - this is what stops an attacker who can
    write to the data directory from dropping one file's ciphertext
    where a different file is expected."""
    path_a = os.path.join(tmp_path, "hosts.dta")
    path_b = os.path.join(tmp_path, "shares.dta")
    cryptofile.save(path_a, KEY1, "secretweb-hosts-v1", {"a": 1})
    cryptofile.save(path_b, KEY1, "secretweb-shares-v1", {"b": 2})

    with open(path_b, "rb") as f:
        swapped = f.read()
    with open(path_a, "wb") as f:
        f.write(swapped)

    with pytest.raises(cryptofile.InvalidCryptoFileError):
        cryptofile.load(path_a, KEY1, "secretweb-hosts-v1")


def test_truncated_file_rejected(tmp_path):
    path = os.path.join(tmp_path, "hosts.dta")
    cryptofile.save(path, KEY1, PURPOSE, {"a": 1})
    with open(path, "rb") as f:
        blob = f.read()
    with pytest.raises(cryptofile.InvalidCryptoFileError):
        cryptofile.decrypt(KEY1, PURPOSE, blob[:5])


def test_bad_magic_rejected():
    blob = b"XXXX" + b"\x01" + os.urandom(12) + os.urandom(32)
    with pytest.raises(cryptofile.InvalidCryptoFileError):
        cryptofile.decrypt(KEY1, PURPOSE, blob)


def test_unsupported_version_rejected():
    blob = cryptofile.MAGIC + bytes([99]) + os.urandom(12) + os.urandom(32)
    with pytest.raises(cryptofile.InvalidCryptoFileError):
        cryptofile.decrypt(KEY1, PURPOSE, blob)


def test_encrypt_uses_fresh_nonce_each_time():
    plaintext = b'{"a": 1}'
    blob1 = cryptofile.encrypt(KEY1, PURPOSE, plaintext)
    blob2 = cryptofile.encrypt(KEY1, PURPOSE, plaintext)
    assert blob1 != blob2  # same plaintext, same key -> must not repeat ciphertext


def test_ensure_mirrored_creates_default_and_writes_both_files(tmp_path):
    calls = []

    def default_factory():
        calls.append(1)
        return {"sites": {}}

    data = cryptofile.ensure_mirrored(
        str(tmp_path), "sites.dta", "sites.json", KEY1, "secretweb-sites-v1", default_factory,
    )

    assert data == {"sites": {}}
    assert len(calls) == 1
    assert cryptofile.load(os.path.join(tmp_path, "sites.dta"), KEY1, "secretweb-sites-v1") == data
    with open(os.path.join(tmp_path, "sites.json"), "rb") as f:
        assert json.load(f) == data


def test_ensure_mirrored_loads_existing_without_calling_default_factory(tmp_path):
    cryptofile.save(os.path.join(tmp_path, "sites.dta"), KEY1, "secretweb-sites-v1", {"sites": {"a": 1}})

    def default_factory():
        raise AssertionError("default_factory should not be called when the file already exists")

    data = cryptofile.ensure_mirrored(
        str(tmp_path), "sites.dta", "sites.json", KEY1, "secretweb-sites-v1", default_factory,
    )
    assert data == {"sites": {"a": 1}}


def test_save_mirrored_writes_identical_content_to_both_files(tmp_path):
    data = {"hosts": {"h1": {"port": 1234}}}
    cryptofile.save_mirrored(str(tmp_path), "hosts.dta", "hosts.json", KEY1, PURPOSE, data)

    encrypted = cryptofile.load(os.path.join(tmp_path, "hosts.dta"), KEY1, PURPOSE)
    with open(os.path.join(tmp_path, "hosts.json"), "rb") as f:
        plaintext = json.load(f)

    assert encrypted == data
    assert plaintext == data


def test_ensure_creates_default_with_no_plaintext_mirror(tmp_path):
    path = os.path.join(tmp_path, "secrets.dta")
    calls = []

    def default_factory():
        calls.append(1)
        return {"secrets": {}}

    data = cryptofile.ensure(path, KEY1, "secretweb-secrets-v1", default_factory)

    assert data == {"secrets": {}}
    assert len(calls) == 1
    assert cryptofile.load(path, KEY1, "secretweb-secrets-v1") == data
    assert os.listdir(tmp_path) == ["secrets.dta"]  # nothing else written


def test_ensure_loads_existing_without_calling_default_factory(tmp_path):
    path = os.path.join(tmp_path, "secrets.dta")
    cryptofile.save(path, KEY1, "secretweb-secrets-v1", {"secrets": {"s1": {"treshold": 3}}})

    def default_factory():
        raise AssertionError("default_factory should not be called when the file already exists")

    data = cryptofile.ensure(path, KEY1, "secretweb-secrets-v1", default_factory)
    assert data == {"secrets": {"s1": {"treshold": 3}}}


def test_ensure_raises_if_existing_file_undecryptable(tmp_path):
    path = os.path.join(tmp_path, "secrets.dta")
    cryptofile.save(path, "a-different-key1", "secretweb-secrets-v1", {"secrets": {}})

    with pytest.raises(cryptofile.InvalidCryptoFileError):
        cryptofile.ensure(path, KEY1, "secretweb-secrets-v1", lambda: {"secrets": {}})
