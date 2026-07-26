import configparser
import json
import os
import shutil
import socket
import subprocess
import time

import pytest
from click.testing import CliRunner

import cryptofile
import initiator
import secretweb_client
import server

TEST_CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
PEER_KEY1 = "test-peer-key1-0123456789abcdef"


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


def _spawn_peer(tmp_path, address: str, port: int) -> subprocess.Popen:
    """A real server.py instance bound to address:port, standing in for
    one trusted peer - just accepts shares, no special identity needed."""
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

    proc = initiator.start_server(str(basedir), str(config_file), PEER_KEY1)
    _wait_for_port(address, port)
    return proc


@pytest.fixture
def network(tmp_path):
    """Three real peer servers (127.0.0.13/.14/.15) sharing one port, plus
    an "own" host (127.0.0.12, identified as good-client) that is ALSO a
    real running server - secretweb_client.py talks to its own local
    server to record a created secret, exactly like production, so the
    "own" side needs a live server too, not just a client config. own's
    hosts.dta/hosts.json both mark good-client as local and the three
    peers as trusted."""
    port = _free_port()
    peer_addrs = ("127.0.0.13", "127.0.0.14", "127.0.0.15")
    peers = [_spawn_peer(tmp_path, addr, port) for addr in peer_addrs]

    own_dir = tmp_path / "own"
    cert_dir = own_dir / "certificates"
    cert_dir.mkdir(parents=True)
    shutil.copy(os.path.join(TEST_CERTS_DIR, "good_client.crt"), cert_dir / "cert.pem")
    shutil.copy(os.path.join(TEST_CERTS_DIR, "good_client.key"), cert_dir / "private.pem")
    shutil.copy(os.path.join(TEST_CERTS_DIR, "ca.crt"), cert_dir / "ca.crt")

    data_dir = own_dir / "data"
    data_dir.mkdir()
    config_file = data_dir / "config.ini"
    config = configparser.ConfigParser()
    config["secretweb"] = {
        "initiated": "False",
        "server-port": str(port),
        # Specifically 127.0.0.1, not 0.0.0.0 - secretweb_client.py's local
        # record_secret call dials 127.0.0.1 (matching real deployments,
        # where bind-address is 0.0.0.0 and so covers it too), and binding
        # the wildcard address here would collide with the peers above
        # already holding this same port on their own specific addresses.
        "bind-address": "127.0.0.1",
        "cert-file": "cert.pem",
        "key-file": "private.pem",
        "ca-file": "ca.crt",
    }
    with open(config_file, "w") as f:
        config.write(f)

    hosts_dict = {
        "hosts": {
            "good-client": {"status": "local", "address": "127.0.0.1", "port": port},
            "peer-a": {"status": "default", "address": "127.0.0.13", "port": port},
            "peer-b": {"status": "default", "address": "127.0.0.14", "port": port},
            "peer-c": {"status": "default", "address": "127.0.0.15", "port": port},
        }
    }
    cryptofile.save(
        str(data_dir / server.HOSTS_FILENAME), PEER_KEY1, server.HOSTS_FILE_PURPOSE, hosts_dict,
    )
    with open(data_dir / "hosts.json", "w") as f:
        json.dump(hosts_dict, f)

    own_proc = initiator.start_server(str(own_dir), str(config_file), PEER_KEY1)
    _wait_for_port("127.0.0.1", port)

    try:
        yield {"own_basedir": str(own_dir), "port": port, "peers": peers}
    finally:
        for proc in (*peers, own_proc):
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def test_store_secret_succeeds_with_all_peers_up(network):
    runner = CliRunner()
    result = runner.invoke(
        secretweb_client.cli,
        [
            "store-secret", "--name", "my-secret", "--secret", "hunter2",
            "--basedir", network["own_basedir"],
        ],
    )

    assert result.exit_code == 0, result.output
    assert "OK" in result.output


def test_store_secret_succeeds_when_one_peer_is_down(network):
    # 3 trusted peers -> default treshold is 2 (majority) - killing one
    # peer still leaves enough to meet it.
    down_peer = network["peers"][0]
    down_peer.terminate()
    down_peer.wait(timeout=3)

    runner = CliRunner()
    result = runner.invoke(
        secretweb_client.cli,
        [
            "store-secret", "--name", "my-secret", "--secret", "hunter2",
            "--basedir", network["own_basedir"],
        ],
    )

    assert result.exit_code == 0, result.output
    assert "OK" in result.output


def test_store_secret_fails_clearly_when_too_many_peers_are_down(network):
    # Only 1 of 3 peers left - can't meet the default treshold of 2.
    for proc in network["peers"][:2]:
        proc.terminate()
        proc.wait(timeout=3)

    runner = CliRunner()
    result = runner.invoke(
        secretweb_client.cli,
        [
            "store-secret", "--name", "my-secret", "--secret", "hunter2",
            "--basedir", network["own_basedir"],
        ],
    )

    assert result.exit_code != 0
    assert "FAILED" in result.output
    assert "not recorded locally" in result.output


def test_store_secret_reads_from_stdin_when_secret_option_omitted(network):
    runner = CliRunner()
    result = runner.invoke(
        secretweb_client.cli,
        ["store-secret", "--name", "stdin-secret", "--basedir", network["own_basedir"]],
        input="hunter2\n",
    )

    assert result.exit_code == 0, result.output


def _store_secret(network, name, secret):
    runner = CliRunner()
    result = runner.invoke(
        secretweb_client.cli,
        ["store-secret", "--name", name, "--secret", secret, "--basedir", network["own_basedir"]],
    )
    assert result.exit_code == 0, result.output


def test_get_secret_reconstructs_a_previously_stored_secret(network):
    _store_secret(network, "roundtrip-secret", "hunter2")

    runner = CliRunner()
    result = runner.invoke(
        secretweb_client.cli,
        ["get-secret", "--name", "roundtrip-secret", "--basedir", network["own_basedir"]],
    )

    assert result.exit_code == 0, result.output
    # stdout carries *only* the secret - progress goes to stderr - so this
    # is meant to be pipeable without extra parsing.
    assert result.stdout == "hunter2\n"


def test_get_secret_succeeds_when_one_peer_is_down(network):
    _store_secret(network, "roundtrip-secret", "hunter2")

    down_peer = network["peers"][0]
    down_peer.terminate()
    down_peer.wait(timeout=3)

    runner = CliRunner()
    result = runner.invoke(
        secretweb_client.cli,
        ["get-secret", "--name", "roundtrip-secret", "--basedir", network["own_basedir"]],
    )

    assert result.exit_code == 0, result.output
    assert result.stdout == "hunter2\n"


def test_get_secret_fails_clearly_when_too_many_peers_are_down(network):
    _store_secret(network, "roundtrip-secret", "hunter2")

    for proc in network["peers"][:2]:
        proc.terminate()
        proc.wait(timeout=3)

    runner = CliRunner()
    result = runner.invoke(
        secretweb_client.cli,
        ["get-secret", "--name", "roundtrip-secret", "--basedir", network["own_basedir"]],
    )

    assert result.exit_code != 0
    assert result.stdout == ""


def test_get_secret_fails_clearly_for_unknown_name(network):
    runner = CliRunner()
    result = runner.invoke(
        secretweb_client.cli,
        ["get-secret", "--name", "never-created", "--basedir", network["own_basedir"]],
    )

    assert result.exit_code != 0
    assert result.stdout == ""


def test_store_secret_rejects_shares_exceeding_trusted_peer_count(network):
    runner = CliRunner()
    result = runner.invoke(
        secretweb_client.cli,
        [
            "store-secret", "--name", "x", "--secret", "y", "--shares", "10",
            "--basedir", network["own_basedir"],
        ],
    )

    assert result.exit_code != 0
