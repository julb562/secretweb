import configparser
import json
import os
import shutil
import socket
import subprocess
import time

import pytest

import initiator
import peer_client
import shamir

TEST_CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(address: str, port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((address, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"nothing listening on {address}:{port} after {timeout}s")


def _spawn_peer(tmp_path, address: str, port: int):
    """A real server.py instance bound to `address`:`port`, standing in
    for one peer host. Its own KEY1 is arbitrary - only used to encrypt
    its own hosts.dta etc., irrelevant to the shares it's asked to store."""
    basedir = tmp_path / address
    cert_dir = basedir / "certificates"
    cert_dir.mkdir(parents=True)
    for name in ("server.crt", "server.key", "ca.crt"):
        shutil.copy(os.path.join(TEST_CERTS_DIR, name), cert_dir / name)

    data_dir = basedir / "data"
    data_dir.mkdir()
    config_file = data_dir / "config.ini"
    config = configparser.ConfigParser()
    config["secretweb"] = {
        "initiated": "False",
        "server-port": str(port),
        "bind-address": address,
        "cert-file": "server.crt",
        "key-file": "server.key",
        "ca-file": "ca.crt",
    }
    with open(config_file, "w") as f:
        config.write(f)

    proc = initiator.start_server(str(basedir), str(config_file), "peer-key1")
    _wait_for_port(address, port)
    return proc


@pytest.fixture
def peer_network(tmp_path):
    """Two real peer servers (127.0.0.3, 127.0.0.4) sharing one port -
    matching the app's existing "every host record carries the same port"
    data model (see setup_secretweb._build_hosts_data()) - plus an "own"
    basedir (own_dir) identified as good-client (tests/certs/good_client.*),
    with hosts.json already describing all three. Nothing is published to
    the peers yet - tests do that themselves via peer_client.store_share()."""
    port = _free_port()
    peer3 = _spawn_peer(tmp_path, "127.0.0.3", port)
    peer4 = _spawn_peer(tmp_path, "127.0.0.4", port)

    own_dir = tmp_path / "own"
    cert_dir = own_dir / "certificates"
    cert_dir.mkdir(parents=True)
    shutil.copy(os.path.join(TEST_CERTS_DIR, "good_client.crt"), cert_dir / "cert.pem")
    shutil.copy(os.path.join(TEST_CERTS_DIR, "good_client.key"), cert_dir / "private.pem")
    shutil.copy(os.path.join(TEST_CERTS_DIR, "ca.crt"), cert_dir / "ca.crt")

    data_dir = own_dir / "data"
    data_dir.mkdir()
    hosts_data = {
        "hosts": {
            "good-client": {"status": "local", "address": "127.0.0.2", "port": port},
            "peer3": {"status": "default", "address": "127.0.0.3", "port": port},
            "peer4": {"status": "default", "address": "127.0.0.4", "port": port},
        }
    }
    with open(data_dir / "hosts.json", "w") as f:
        json.dump(hosts_data, f)

    try:
        yield {"own_basedir": str(own_dir), "port": port}
    finally:
        for proc in (peer3, peer4):
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def _own_config(peer_network, treshold=2):
    config = configparser.ConfigParser()
    config["secretweb"] = {
        "server-port": str(peer_network["port"]),
        "cert-file": "cert.pem",
        "key-file": "private.pem",
        "ca-file": "ca.crt",
        "key1-name": "key1",
        "key1-uuid": "",  # filled in per-test after publishing
        "key1-treshold": str(treshold),
        "key1-shares": "2",
    }
    return config


def _publish_key1(peer_network, key1_value, treshold=2):
    """Shamir-splits key1_value into 2 shares (one per peer) and stores
    them, as good-client, exactly as setup_secretweb._publish_key1_to_network()
    would."""
    secret = shamir.ShamirSecret("key1", "good-client", shares=2, treshold=treshold)
    secret.create_secret(key1_value)
    cert_file = os.path.join(peer_network["own_basedir"], "certificates", "cert.pem")
    key_file = os.path.join(peer_network["own_basedir"], "certificates", "private.pem")
    ca_file = os.path.join(peer_network["own_basedir"], "certificates", "ca.crt")
    port = peer_network["port"]
    for address, participant_data in zip(("127.0.0.3", "127.0.0.4"), secret.iterate_participants()):
        peer_client.store_share(address, port, cert_file, key_file, ca_file, participant_data)
    return secret.uuid


def test_collect_key1_reconstructs_with_all_peers_up(peer_network):
    config = _own_config(peer_network)
    key1_uuid = _publish_key1(peer_network, "the-real-key1-value")
    config["secretweb"]["key1-uuid"] = key1_uuid

    result = initiator._collect_key1(peer_network["own_basedir"], config)

    assert result == "the-real-key1-value"


def test_collect_key1_succeeds_with_unreachable_peer_declared_in_hosts(peer_network, tmp_path):
    # A third, never-started peer is in hosts.json - treshold only needs 2,
    # and only 2 real shares were ever published (to 127.0.0.3/.4), so
    # reconstruction must skip the phantom peer rather than getting stuck.
    hosts_path = os.path.join(peer_network["own_basedir"], "data", "hosts.json")
    with open(hosts_path) as f:
        hosts_data = json.load(f)
    hosts_data["hosts"]["ghost"] = {"status": "default", "address": "127.0.0.5", "port": peer_network["port"]}
    with open(hosts_path, "w") as f:
        json.dump(hosts_data, f)

    config = _own_config(peer_network)
    key1_uuid = _publish_key1(peer_network, "still-the-real-value")
    config["secretweb"]["key1-uuid"] = key1_uuid

    result = initiator._collect_key1(peer_network["own_basedir"], config)

    assert result == "still-the-real-value"


def test_collect_key1_raises_on_missing_config_metadata(peer_network):
    config = configparser.ConfigParser()
    config["secretweb"] = {"server-port": str(peer_network["port"])}

    with pytest.raises(initiator.Key1ReconstructionError):
        initiator._collect_key1(peer_network["own_basedir"], config)


def test_own_host_entry_requires_a_local_status_host():
    with pytest.raises(initiator.Key1ReconstructionError):
        initiator._own_host_entry({"hosts": {"a": {"status": "default"}}})


def test_own_host_entry_finds_the_local_one():
    hosts_data = {"hosts": {"a": {"status": "default"}, "b": {"status": "local"}}}
    assert initiator._own_host_entry(hosts_data) == {"name": "b", "status": "local"}


def test_trusted_peers_excludes_self_and_untrusted_statuses():
    hosts_data = {
        "hosts": {
            "me": {"status": "local"},
            "good": {"status": "default"},
            "bad": {"status": "compromised"},
            "gone": {"status": "deleted"},
        }
    }
    peers = initiator._trusted_peers(hosts_data, "me")
    assert {p["name"] for p in peers} == {"good"}


def test_collect_key1_keeps_retrying_instead_of_giving_up(monkeypatch):
    """No bounded number of rounds - one of two required peers only
    starts answering after a couple of rounds, and reconstruction must
    still succeed instead of raising early. time.sleep is stubbed so this
    doesn't actually wait in real time."""
    secret = shamir.ShamirSecret("key1", "me", shares=2, treshold=2)
    secret.create_secret("eventual-value")
    share_by_address = dict(zip(("127.0.0.10", "127.0.0.11"), secret.iterate_participants()))

    calls = {"count": 0}

    def fake_retrieve_share(address, port, cert_file, key_file, ca_file, share_uuid):
        if address == "127.0.0.11":
            calls["count"] += 1
            if calls["count"] < 3:
                raise peer_client.ShareNotFoundError("not yet")
        return share_by_address[address]

    monkeypatch.setattr(peer_client, "retrieve_share", fake_retrieve_share)
    monkeypatch.setattr(initiator.time, "sleep", lambda seconds: None)

    hosts_data = {
        "hosts": {
            "me": {"status": "local", "address": "127.0.0.9", "port": 1},
            "peer-a": {"status": "default", "address": "127.0.0.10", "port": 1},
            "peer-b": {"status": "default", "address": "127.0.0.11", "port": 1},
        }
    }
    monkeypatch.setattr(initiator, "_load_hosts_json", lambda basedir: hosts_data)

    config = configparser.ConfigParser()
    config["secretweb"] = {
        "server-port": "1",
        "cert-file": "cert.pem",
        "key-file": "private.pem",
        "ca-file": "ca.crt",
        "key1-name": "key1",
        "key1-uuid": secret.uuid,
        "key1-treshold": "2",
        "key1-shares": "2",
    }

    result = initiator._collect_key1("/irrelevant", config)

    assert result == "eventual-value"
    assert calls["count"] >= 3
