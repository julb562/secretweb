"""
Boot-time initiator: on an already-bootstrapped host (config.ini's
`initiated` is true - set by setup_secretweb.py's one-time interactive
bootstrap), reconstructs this host's own KEY1 from peer shares (see
_collect_key1()), matching the boot algorithm in mynotes/Initials.txt -
look up own key1's name/uuid/treshold, ask trusted peers for shares in
random order until treshold is met, decrypt - then spawns server.py and
hands it KEY1 over a socketpair, per key_handoff.py. Not yet initiated
means there's nothing to reconstruct or start yet: setup_secretweb.py
starts the server itself, directly, during that first bootstrap.

Also tracks the spawned server's pid so a later `--stop` (e.g. from a
systemd ExecStop, since server.py can't be a normal supervised service -
see start_server()'s docstring) has something to stop.
"""
import configparser
import os
import random
import signal
import socket
import subprocess
import sys
import time

import click

import cryptofile
import hosts_data
import key_handoff
import peer_client
import shamir

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BASEDIR = SCRIPT_DIR
SERVER_SCRIPT = os.path.join(SCRIPT_DIR, "server.py")

PID_FILENAME = "server.pid"
POLL_INTERVAL_SECONDS = 10


class Key1ReconstructionError(Exception):
    """Something structurally wrong (e.g. key1 metadata missing from
    config.ini, or no trusted peers in hosts.json) that no amount of
    retrying peers would fix - distinct from shamir.ShareReconstructionError,
    which means enough shares were collected but they don't validate."""


def load_config(config_file: str) -> configparser.ConfigParser:
    """Reads config.ini."""
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def _cert_paths(basedir: str, config: configparser.ConfigParser) -> tuple:
    cert_dir = os.path.join(basedir, "certificates")
    cert_file = os.path.join(cert_dir, config.get("secretweb", "cert-file", fallback="cert.pem"))
    key_file = os.path.join(cert_dir, config.get("secretweb", "key-file", fallback="private.pem"))
    ca_file = os.path.join(cert_dir, config.get("secretweb", "ca-file", fallback="ca.crt"))
    return cert_file, key_file, ca_file


def _collect_key1(basedir: str, config: configparser.ConfigParser) -> str:
    """Reconstructs this host's own KEY1 from peer shares. No bounded
    number of retry rounds - same reasoning as
    setup_secretweb.py._poll_for_hosts_online(): this can take as long as
    the network takes to come back up, and `systemctl stop` is the
    operator's way to abort if needed, not an arbitrary timeout here."""
    section = config["secretweb"]
    try:
        key1_name = section["key1-name"]
        key1_uuid = section["key1-uuid"]
        key1_treshold = section.getint("key1-treshold")
        key1_shares = section.getint("key1-shares")
    except KeyError as exc:
        raise Key1ReconstructionError(
            f"config.ini is missing key1 metadata ({exc}) - this host hasn't "
            "had key1 published to it yet (see setup_secretweb.py)"
        ) from exc

    hosts = hosts_data.load_hosts_json(basedir)
    try:
        own_host = hosts_data.own_host_entry(hosts)
    except hosts_data.OwnHostNotFoundError as exc:
        raise Key1ReconstructionError(str(exc)) from exc
    peers = hosts_data.trusted_peers(hosts, own_host["name"])
    if not peers:
        raise Key1ReconstructionError("no trusted peers in hosts.json to ask for key1 shares")

    cert_file, key_file, ca_file = _cert_paths(basedir, config)
    port = config.getint("secretweb", "server-port")

    decoder = shamir.ShamirSecret(
        key1_name, own_host["name"], shares=key1_shares, treshold=key1_treshold,
    )

    contributed = set()
    while not decoder.ready_to_decode:
        candidates = [p for p in peers if p["name"] not in contributed]
        random.shuffle(candidates)
        for peer in candidates:
            if decoder.ready_to_decode:
                break
            try:
                participant_data = peer_client.retrieve_share(
                    peer["address"], port, cert_file, key_file, ca_file, key1_uuid,
                )
            except (OSError, peer_client.ShareNotFoundError, peer_client.PeerRequestError):
                continue
            try:
                decoder.populate_decoder(participant_data)
            except shamir.InvalidShareError:
                continue
            contributed.add(peer["name"])
        if not decoder.ready_to_decode:
            time.sleep(POLL_INTERVAL_SECONDS)

    return decoder.decode()


def _pid_file_path(basedir: str) -> str:
    return os.path.join(basedir, "data", PID_FILENAME)


def _pid_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, just not ours to signal - still alive
    return True


def start_server(basedir: str, config_file: str, key1: str) -> subprocess.Popen:
    """Spawns server.py as an independent child process and hands it KEY1
    over a socketpair, blocking until the server reports it actually
    started (port bound), not just that it received KEY1. Raises
    key_handoff.ServerStartupError if the server reports or is inferred
    to have failed to start - no pidfile is written in that case. The
    server process is left running after this returns; it is not attached
    to or supervised by this process beyond the handoff itself -
    start_new_session detaches it into its own session/process group so a
    signal sent to this process (or to its terminal's foreground process
    group, e.g. Ctrl+C) doesn't also reach the server. That detachment
    also means server.py can never be a normal systemd Restart=on-failure
    service: it only ever receives KEY1 through this one-shot handoff at
    spawn time (by design - key_handoff.py exists specifically so KEY1
    never touches argv/env), so a crashed server.py can't simply be
    restarted in place. The pidfile written on success (see stop_server())
    is what lets a systemd ExecStop actually stop it."""
    parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    proc = subprocess.Popen(
        [
            sys.executable,
            SERVER_SCRIPT,
            "--basedir", basedir,
            "--config-file", config_file,
            "--key-fd", str(child_sock.fileno()),
        ],
        pass_fds=(child_sock.fileno(),),
        start_new_session=True,
    )
    child_sock.close()
    try:
        key_handoff.send_key1(parent_sock, key1)
    finally:
        parent_sock.close()
    cryptofile.atomic_write_bytes(_pid_file_path(basedir), str(proc.pid).encode("utf-8"))
    return proc


def stop_server(basedir: str, timeout: float = 5.0) -> bool:
    """Stops the server previously started against this basedir, using the
    pidfile start_server() wrote. A no-op success (returns False) if
    there's no pidfile or the pid it names is already dead - matches what
    a systemd stop action expects: stopping an already-stopped service
    isn't an error. Does not verify the pid still belongs to a secretweb
    server process (e.g. via /proc/<pid>/cmdline) - a stale pidfile whose
    pid has since been reused by an unrelated process is a known, accepted
    gap, not handled here."""
    pid_path = _pid_file_path(basedir)
    try:
        with open(pid_path) as f:
            pid = int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return False

    stopped = False
    if _pid_is_alive(pid):
        os.kill(pid, signal.SIGTERM)
        deadline = time.time() + timeout
        while time.time() < deadline and _pid_is_alive(pid):
            time.sleep(0.1)
        if _pid_is_alive(pid):
            os.kill(pid, signal.SIGKILL)
        stopped = True

    try:
        os.unlink(pid_path)
    except FileNotFoundError:
        pass
    return stopped


@click.command()
@click.option(
    "--basedir",
    default=DEFAULT_BASEDIR,
    show_default=True,
    help="Project base directory (holds data/ and certificates/ subdirectories).",
)
@click.option(
    "--config-file",
    default=None,
    help="Path to config.ini. Defaults to <basedir>/data/config.ini.",
)
@click.option(
    "--stop",
    "stop",
    is_flag=True,
    help="Stop a previously started server using its pidfile, instead of starting one.",
)
def main(basedir: str, config_file: str, stop: bool) -> None:
    """Checks initiation status: if not yet initiated (setup_secretweb.py
    hasn't bootstrapped this host), there's nothing to reconstruct or
    start, so this is a no-op. If initiated, this is a normal (or
    systemd) boot: reconstruct KEY1 from peer shares (see
    _collect_key1()) and start the server for real. With --stop, stops a
    previously started server instead (see stop_server()) - this is what
    a systemd ExecStop calls."""
    if stop:
        if stop_server(basedir):
            click.echo("status: OK - server stopped")
        else:
            click.echo("status: OK - nothing to stop")
        return

    if config_file is None:
        config_file = os.path.join(basedir, "data", "config.ini")

    config = load_config(config_file)
    initiated = config.getboolean("secretweb", "initiated", fallback=False)

    if not initiated:
        click.echo("status: not yet initiated - nothing to do (run setup_secretweb.py first)")
        return

    try:
        key1 = _collect_key1(basedir, config)
    except (Key1ReconstructionError, shamir.ShareReconstructionError) as exc:
        click.echo(f"status: FAILED to reconstruct key1: {exc}")
        sys.exit(1)

    try:
        start_server(basedir, config_file, key1)
    except (OSError, key_handoff.ServerStartupError) as exc:
        click.echo(f"status: FAILED to start server: {exc}")
        sys.exit(1)

    click.echo("status: OK - key1 reconstructed, server started, port bound")


if __name__ == "__main__":
    main()
