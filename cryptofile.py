"""
Encrypted-at-rest JSON document store for this host's local data files
(data/hosts.dta today; saved shares/sites/own-secrets files later). Each
file is independently authenticated-encrypted (AES-256-GCM) with a subkey
derived from KEY1 via HKDF, bound to a short "purpose" label both in the
key derivation and as AEAD associated data - so ciphertext from one file
can never be silently substituted for another, even under key reuse.

Whole-file encryption, not streaming or incremental - these files are
expected to stay small (host lists, share metadata), so re-encrypting the
entire document on every write keeps the format and code simple.

Documents are plain JSON dicts. Callers should always read fields with
.get(name, default) rather than direct indexing, so that older on-disk
files missing a newly-added field - or newer files carrying fields an
older build doesn't know about yet - don't break: additions to the schema
should be purely additive, never require a migration to keep loading.
"""
import json
import os
import secrets
import struct
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SWCF"
VERSION = 1

_HEADER = struct.Struct("!4sB")
_NONCE_SIZE = 12
_KEY_SIZE = 32


class CryptoFileError(Exception):
    """Base class for cryptofile failures."""


class InvalidCryptoFileError(CryptoFileError):
    """Raised when a file's envelope is malformed, an unsupported
    version, or fails authentication - wrong key, wrong purpose, or the
    file was tampered with or corrupted all land here."""


def _derive_key(key1: str, purpose: str) -> bytes:
    """Derives a purpose-bound AES-256 key from KEY1 via HKDF-SHA256. No
    salt: KEY1 is machine-generated with strong entropy already."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_SIZE,
        salt=None,
        info=purpose.encode("utf-8"),
    )
    return hkdf.derive(key1.encode("utf-8"))


def _aad(purpose: str) -> bytes:
    return MAGIC + bytes([VERSION]) + purpose.encode("utf-8")


def encrypt(key1: str, purpose: str, plaintext: bytes) -> bytes:
    """Encrypts plaintext into a self-contained envelope: magic, version,
    a fresh random nonce, then AEAD ciphertext+tag."""
    key = _derive_key(key1, purpose)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _aad(purpose))
    return _HEADER.pack(MAGIC, VERSION) + nonce + ciphertext


def decrypt(key1: str, purpose: str, blob: bytes) -> bytes:
    """Reverses encrypt(). Raises InvalidCryptoFileError on any envelope
    or authentication failure rather than returning garbage."""
    header_size = _HEADER.size
    if len(blob) < header_size + _NONCE_SIZE:
        raise InvalidCryptoFileError("file too short to be a valid cryptofile")

    magic, version = _HEADER.unpack(blob[:header_size])
    if magic != MAGIC:
        raise InvalidCryptoFileError("bad magic - not a cryptofile")
    if version != VERSION:
        raise InvalidCryptoFileError(f"unsupported cryptofile version: {version}")

    nonce = blob[header_size:header_size + _NONCE_SIZE]
    ciphertext = blob[header_size + _NONCE_SIZE:]
    key = _derive_key(key1, purpose)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _aad(purpose))
    except (InvalidTag, ValueError) as exc:
        raise InvalidCryptoFileError(
            "decryption failed - wrong key, wrong purpose, or the file is "
            "tampered with or corrupted"
        ) from exc


def atomic_write_bytes(path: str, data: bytes) -> None:
    """Writes data to path atomically (temp file + rename) so a crash
    mid-write never leaves a half-written file behind. Used by save()
    for encrypted envelopes, and available to callers that write a
    plaintext companion file alongside one (e.g. server.py's hosts.json)."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def save(path: str, key1: str, purpose: str, data: dict) -> None:
    """Serializes data as JSON, encrypts it, and writes it atomically."""
    plaintext = json.dumps(data).encode("utf-8")
    blob = encrypt(key1, purpose, plaintext)
    atomic_write_bytes(path, blob)


def load(path: str, key1: str, purpose: str) -> dict:
    """Reads, decrypts, and JSON-deserializes a file written by save()."""
    with open(path, "rb") as f:
        blob = f.read()
    return json.loads(decrypt(key1, purpose, blob))


def ensure(path: str, key1: str, purpose: str, default_factory) -> dict:
    """Loads path, creating it (encrypted-only, no plaintext mirror) from
    default_factory() if it doesn't exist yet. Use this for genuinely
    sensitive data that must never be written unencrypted - see
    ensure_mirrored() for the dual-write variant for non-sensitive data."""
    if not os.path.exists(path):
        data = default_factory()
        save(path, key1, purpose, data)
        return data
    return load(path, key1, purpose)


def save_mirrored(
    data_dir: str,
    encrypted_filename: str,
    plaintext_filename: str,
    key1: str,
    purpose: str,
    data: dict,
) -> None:
    """Writes an encrypted file plus an identical plaintext JSON mirror
    alongside it, both inside data_dir. Only call this for data that
    genuinely isn't sensitive (e.g. a host list) - encryption there is
    mainly for integrity, not secrecy. Callers holding confidential data
    (shares, secrets) should use save() alone, with no plaintext mirror."""
    save(os.path.join(data_dir, encrypted_filename), key1, purpose, data)
    atomic_write_bytes(
        os.path.join(data_dir, plaintext_filename),
        json.dumps(data, indent=2).encode("utf-8"),
    )


def ensure_mirrored(
    data_dir: str,
    encrypted_filename: str,
    plaintext_filename: str,
    key1: str,
    purpose: str,
    default_factory,
) -> dict:
    """Loads the encrypted file, creating it - and its plaintext mirror -
    from default_factory() if it doesn't exist yet. See save_mirrored()."""
    encrypted_path = os.path.join(data_dir, encrypted_filename)
    if not os.path.exists(encrypted_path):
        data = default_factory()
        save_mirrored(data_dir, encrypted_filename, plaintext_filename, key1, purpose, data)
        return data
    return load(encrypted_path, key1, purpose)
