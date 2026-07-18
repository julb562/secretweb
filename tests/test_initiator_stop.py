import os
import subprocess

import initiator
from conftest import _wait_for_port


def test_start_server_writes_pid_file(server_env):
    proc = initiator.start_server(
        server_env["basedir"], server_env["config_file"], "test-key1",
    )
    try:
        pid_path = os.path.join(server_env["basedir"], "data", initiator.PID_FILENAME)
        assert os.path.exists(pid_path)
        with open(pid_path) as f:
            assert int(f.read().strip()) == proc.pid
        assert initiator._pid_is_alive(proc.pid)
    finally:
        proc.terminate()
        proc.wait(timeout=3)


def test_stop_server_terminates_running_server_and_removes_pid_file(server_env):
    proc = initiator.start_server(
        server_env["basedir"], server_env["config_file"], "test-key1",
    )
    _wait_for_port(server_env["port"])
    pid_path = os.path.join(server_env["basedir"], "data", initiator.PID_FILENAME)

    stopped = initiator.stop_server(server_env["basedir"])
    # stop_server() signals the process directly (os.kill), bypassing
    # Popen's own bookkeeping - reap it here the same way its real parent
    # (init/systemd, once detached) would, so the liveness check below
    # isn't fooled by an unreaped zombie that still answers kill(pid, 0).
    proc.wait(timeout=3)

    assert stopped is True
    assert not initiator._pid_is_alive(proc.pid)
    assert not os.path.exists(pid_path)


def test_stop_server_with_no_pid_file_is_a_noop(server_env):
    assert initiator.stop_server(server_env["basedir"]) is False


def test_stop_server_with_stale_pid_removes_file_and_returns_false(server_env):
    dead = subprocess.Popen(["true"])
    dead.wait(timeout=3)

    pid_path = os.path.join(server_env["basedir"], "data", initiator.PID_FILENAME)
    os.makedirs(os.path.dirname(pid_path), exist_ok=True)
    with open(pid_path, "w") as f:
        f.write(str(dead.pid))

    stopped = initiator.stop_server(server_env["basedir"])

    assert stopped is False
    assert not os.path.exists(pid_path)


def test_cli_stop_flag_invokes_stop_server(server_env):
    proc = initiator.start_server(
        server_env["basedir"], server_env["config_file"], "test-key1",
    )
    _wait_for_port(server_env["port"])
    pid_path = os.path.join(server_env["basedir"], "data", initiator.PID_FILENAME)

    result = subprocess.run(
        [
            "python3", initiator.__file__, "--stop",
            "--basedir", server_env["basedir"],
        ],
        capture_output=True, text=True, timeout=10, check=False,
    )
    proc.wait(timeout=3)  # reap - see comment in the test above

    assert result.returncode == 0
    assert "server stopped" in result.stdout
    assert not initiator._pid_is_alive(proc.pid)
    assert not os.path.exists(pid_path)
