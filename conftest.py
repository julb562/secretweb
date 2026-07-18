import configparser
import os
import shutil
import socket
import subprocess
import time

import pytest

import initiator

TEST_CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests", "certs")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"nothing listening on port {port} after {timeout}s")


@pytest.fixture
def server_env(tmp_path):
    """A throwaway <basedir> with its own certificates/ and data/config.ini,
    isolated from the real project's certificates/ - server.py itself is
    still resolved from the real repo (see initiator.SERVER_SCRIPT)."""
    cert_dir = tmp_path / "certificates"
    cert_dir.mkdir()
    for name in ("server.crt", "server.key", "ca.crt"):
        shutil.copy(os.path.join(TEST_CERTS_DIR, name), cert_dir / name)

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    config_file = data_dir / "config.ini"
    port = _free_port()

    config = configparser.ConfigParser()
    config["secretweb"] = {
        "initiated": "False",
        "server-port": str(port),
        "bind-address": "127.0.0.1",
        "cert-file": "server.crt",
        "key-file": "server.key",
        "ca-file": "ca.crt",
    }
    with open(config_file, "w") as f:
        config.write(f)

    return {"basedir": str(tmp_path), "config_file": str(config_file), "port": port}


@pytest.fixture
def spawned_server(server_env):
    proc = initiator.start_server(server_env["basedir"], server_env["config_file"], "test-key1")
    _wait_for_port(server_env["port"])
    try:
        yield server_env["port"]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
