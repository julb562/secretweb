"""
First draft of the boot-time initiator.

Real responsibilities not implemented yet: host list lookup and share
collection from peer hosts to reconstruct KEY1 (a hardcoded placeholder is
used instead). What is implemented: spawning server.py as an independent
child process and handing it KEY1 over a socketpair, per key_handoff.py -
plus tracking the spawned server's pid so a later `--stop` (e.g. from a
systemd ExecStop, since server.py can't be a normal supervised service -
see start_server()'s docstring) has something to stop.
"""
import configparser
import os
import signal
import socket
import subprocess
import sys
import time

import click

import cryptofile
import key_handoff

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_BASEDIR = SCRIPT_DIR
SERVER_SCRIPT = os.path.join(SCRIPT_DIR, "server.py")

PID_FILENAME = "server.pid"

# Placeholder until real share collection from peer hosts is implemented -
# KEY1 is normally machine-generated per host at network-join time.
HARDCODED_KEY1 = "placeholder-key1-0123456789abcdef"


def load_config(config_file: str) -> configparser.ConfigParser:
    """Reads config.ini."""
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


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
    """Checks initiation status, then spawns server.py and hands it KEY1.
    With --stop, stops a previously started server instead (see
    stop_server()) - this is what a systemd ExecStop calls."""
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

    if initiated:
        click.echo("status: already initiated - nothing to do")
        return

    key1 = HARDCODED_KEY1

    try:
        start_server(basedir, config_file, key1)
    except (OSError, key_handoff.ServerStartupError) as exc:
        click.echo(f"status: FAILED to start server: {exc}")
        sys.exit(1)

    click.echo("status: OK - server started, KEY1 handed off, port bound")


if __name__ == "__main__":
    main()
