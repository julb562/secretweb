"""
Wire protocol for handing KEY1 from the initiator to the server over a
socketpair set up before fork/exec, and for the server to report back
whether it actually started successfully (certs loaded, port bound) - not
just that it received KEY1.
"""
import socket
import struct

_LENGTH_PREFIX = struct.Struct("!I")
_STATUS_OK = b"\x00"
_STATUS_ERR = b"\x01"


class ServerStartupError(Exception):
    """Raised on the initiator side when the server reports it failed to
    start (e.g. certs unreadable, port already in use), or when the
    connection drops before any startup status is received."""


def send_key1(sock: socket.socket, key1: str, timeout: float = 10.0) -> None:
    """Sends KEY1, then blocks (up to timeout) for the server's startup
    status. Raises ServerStartupError if the server reports failure, if
    it never responds in time, or if the connection drops first."""
    payload = key1.encode("utf-8")
    sock.sendall(_LENGTH_PREFIX.pack(len(payload)) + payload)
    sock.settimeout(timeout)
    try:
        status = _recv_exact(sock, 1)
    except (ConnectionError, OSError) as exc:
        raise ServerStartupError(f"server did not report a startup status: {exc}") from exc

    if status == _STATUS_OK:
        return
    if status == _STATUS_ERR:
        raw_length = _recv_exact(sock, _LENGTH_PREFIX.size)
        (length,) = _LENGTH_PREFIX.unpack(raw_length)
        message = _recv_exact(sock, length).decode("utf-8")
        raise ServerStartupError(message)
    raise ServerStartupError(f"unexpected status byte from server: {status!r}")


def receive_key1(sock: socket.socket) -> str:
    """Receives KEY1. The caller must later call send_ready() or
    send_startup_error() on the same socket once it knows whether startup
    (e.g. binding the listening port) actually succeeded."""
    raw_length = _recv_exact(sock, _LENGTH_PREFIX.size)
    (length,) = _LENGTH_PREFIX.unpack(raw_length)
    payload = _recv_exact(sock, length)
    return payload.decode("utf-8")


def send_ready(sock: socket.socket) -> None:
    """Tells the initiator that startup (cert loading, port bind) succeeded."""
    sock.sendall(_STATUS_OK)


def send_startup_error(sock: socket.socket, message: str) -> None:
    """Tells the initiator that startup failed, with a human-readable reason."""
    payload = message.encode("utf-8")
    sock.sendall(_STATUS_ERR + _LENGTH_PREFIX.pack(len(payload)) + payload)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("socket closed before expected data was received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
