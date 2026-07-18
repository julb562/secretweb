import configparser
import http.client
import os
import socket
import ssl

import pytest

import cryptofile
import initiator
import key_handoff

TEST_CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def _https_get(port: int, cert_file: str | None = None, key_file: str | None = None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=os.path.join(TEST_CERTS_DIR, "ca.crt"))
    ctx.check_hostname = False  # test certs are issued for "localhost", dialing by IP
    if cert_file:
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=3)
    try:
        conn.request("GET", "/")
        return conn.getresponse()
    finally:
        conn.close()


def test_start_server_waits_for_actual_port_bind(server_env):
    """start_server() should not return until the port is genuinely bound,
    not merely once KEY1 has been received."""
    proc = initiator.start_server(server_env["basedir"], server_env["config_file"], "test-key1")
    try:
        with socket.create_connection(("127.0.0.1", server_env["port"]), timeout=1):
            pass  # if start_server() returned, the port must already be listening
    finally:
        proc.terminate()
        proc.wait(timeout=3)


def test_spawned_server_is_detached_into_its_own_session(server_env):
    """The server must not share a session/process group with whatever
    spawned it - otherwise a signal delivered to that process's group
    (e.g. a terminal Ctrl+C, which sends SIGINT to the whole foreground
    process group) would also kill the "independently running" server."""
    proc = initiator.start_server(server_env["basedir"], server_env["config_file"], "test-key1")
    try:
        assert os.getsid(proc.pid) != os.getsid(os.getpid())
        assert os.getpgid(proc.pid) != os.getpgid(os.getpid())
    finally:
        proc.terminate()
        proc.wait(timeout=3)


def test_valid_client_cert_gets_200(spawned_server):
    port = spawned_server
    resp = _https_get(
        port,
        os.path.join(TEST_CERTS_DIR, "good_client.crt"),
        os.path.join(TEST_CERTS_DIR, "good_client.key"),
    )
    assert resp.status == 200
    assert resp.read() == b"OK"


def test_client_cert_from_untrusted_ca_rejected(spawned_server):
    port = spawned_server
    with pytest.raises(ssl.SSLError):
        _https_get(
            port,
            os.path.join(TEST_CERTS_DIR, "bad_client.crt"),
            os.path.join(TEST_CERTS_DIR, "bad_client.key"),
        )


def test_missing_client_cert_rejected(spawned_server):
    port = spawned_server
    with pytest.raises(ssl.SSLError):
        _https_get(port)


def test_missing_cert_file_reports_startup_error_to_initiator(server_env):
    config = configparser.ConfigParser()
    config.read(server_env["config_file"])
    config["secretweb"]["cert-file"] = "does-not-exist.crt"
    with open(server_env["config_file"], "w") as f:
        config.write(f)

    with pytest.raises(key_handoff.ServerStartupError):
        initiator.start_server(server_env["basedir"], server_env["config_file"], "test-key1")


def test_port_already_in_use_reports_startup_error_to_initiator(server_env):
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(("127.0.0.1", server_env["port"]))
    blocker.listen(1)
    try:
        with pytest.raises(key_handoff.ServerStartupError):
            initiator.start_server(server_env["basedir"], server_env["config_file"], "test-key1")
    finally:
        blocker.close()


@pytest.mark.parametrize("filename,purpose", [
    ("hosts.dta", "secretweb-hosts-v1"),
    ("sites.dta", "secretweb-sites-v1"),
    ("secrets.dta", "secretweb-secrets-v1"),
])
def test_undecryptable_existing_data_file_reports_startup_error_to_initiator(
    server_env, filename, purpose
):
    """Boot must fail (not silently recreate/skip) if hosts.dta, sites.dta,
    or secrets.dta already exists but can't be decrypted with KEY1."""
    data_path = os.path.join(server_env["basedir"], "data", filename)
    cryptofile.save(data_path, "a-different-key1", purpose, {})

    with pytest.raises(key_handoff.ServerStartupError):
        initiator.start_server(server_env["basedir"], server_env["config_file"], "test-key1")
