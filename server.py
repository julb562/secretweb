"""
First draft of the boot-time server service.

Receives KEY1 from the initiator over an inherited socketpair fd (see
key_handoff.py), ensures data/hosts.dta, data/sites.dta, data/secrets.dta
and data/shares.dta exist (encrypted with KEY1 via cryptofile.py), then
listens for mTLS connections and replies 200 OK.
Client certificate validation against ca.crt happens in the TLS handshake
itself, before any request reaches the application - a request that makes
it here already presented a certificate signed by our trusted CA. The
/shares/<uuid> routes additionally check that a share's claimed owner
matches the connecting client certificate's identity (see
_require_owner_matches_client_cert()), since simply being a trusted host
isn't enough to store or retrieve another host's share. /secrets/<name>
reuses that same check against this server's own identity, so only this
host's own local client (see secretweb_client.py) can ever record or
read back one of this host's own secrets.
"""
from __future__ import annotations

import configparser
import contextlib
import os
import socket
import ssl

import bottle
import click

import cryptofile
import hosts_data
import key_handoff
import shamir
import timeutils

DEFAULT_BASEDIR = os.path.dirname(os.path.abspath(__file__))

HOSTS_FILENAME = "hosts.dta"
HOSTS_PLAINTEXT_FILENAME = hosts_data.HOSTS_PLAINTEXT_FILENAME
HOSTS_FILE_PURPOSE = "secretweb-hosts-v1"

SITES_FILENAME = "sites.dta"
SITES_PLAINTEXT_FILENAME = "sites.json"
SITES_FILE_PURPOSE = "secretweb-sites-v1"

SECRETS_FILENAME = "secrets.dta"
SECRETS_FILE_PURPOSE = "secretweb-secrets-v1"

SHARES_FILENAME = "shares.dta"
SHARES_FILE_PURPOSE = "secretweb-shares-v1"

app = bottle.Bottle()


@app.route("/")
def index():
    """Reachable only after a successful mTLS handshake."""
    return "OK"


def _client_common_name() -> str | None:
    """The Common Name of the certificate the connecting client presented,
    or None if (unexpectedly, since the TLS layer already requires and
    verifies one) it isn't available."""
    peercert = bottle.request.environ.get("peercert")
    if not peercert:
        return None
    for rdn in peercert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def hostname_from_common_name(common_name: str) -> str:
    """A CN may be a bare hostname or a fully-qualified one - only the
    leftmost/hostname label is ever compared against a share's owner.
    Public (not module-private) - setup_secretweb.py reuses this same
    normalization to match this host's own certificate against its typed
    name in the collected host list, see _match_own_host()."""
    return common_name.split(".", 1)[0]


def _require_owner_matches_client_cert(owner: str) -> None:
    """Aborts with 403 unless the connecting client's certificate identity
    matches owner - so one trusted host can't store a bogus share under
    another host's name, or fetch back a share that isn't its own."""
    common_name = _client_common_name()
    if common_name is None:
        bottle.abort(403, "no client certificate identity available")
    if hostname_from_common_name(common_name).lower() != owner.lower():
        bottle.abort(403, "owner does not match client certificate identity")


@app.route("/shares/<share_uuid>", method="POST")
def store_share(share_uuid):
    """Stores a share (one participant_data dict from
    shamir.ShamirSecret.iterate_participants()) handed to this host by the
    secret's owner. Re-submitting the identical share is idempotent; a
    different payload for a uuid already on file is rejected rather than
    silently overwritten."""
    payload = bottle.request.json
    if not isinstance(payload, dict):
        bottle.abort(400, "body must be a JSON object")
    if payload.get("uuid") != share_uuid:
        bottle.abort(400, "uuid in body does not match uuid in path")

    try:
        shamir.ShamirSecret("", "").populate_decoder(payload)
    except (KeyError, shamir.InvalidShareError) as exc:
        bottle.abort(400, f"malformed share: {exc}")

    _require_owner_matches_client_cert(payload["owner"])

    shares = app.config["shares"]["shares"]
    existing = shares.get(share_uuid)
    if existing == payload:
        return {"status": "already-stored"}
    if existing is not None:
        bottle.abort(409, "a different share is already stored for this uuid")

    shares[share_uuid] = payload
    _persist_shares()
    bottle.response.status = 201
    return {"status": "stored"}


@app.route("/shares/<share_uuid>", method="GET")
def get_share(share_uuid):
    """Returns a previously stored share back to its owner - the only
    party allowed to fetch it - keyed by uuid."""
    share = app.config["shares"]["shares"].get(share_uuid)
    if share is None:
        bottle.abort(404, "no share stored for this uuid")
    _require_owner_matches_client_cert(share["owner"])
    return share


def _persist_shares() -> None:
    shares_path = os.path.join(app.config["basedir"], "data", SHARES_FILENAME)
    cryptofile.save(shares_path, app.config["key1"], SHARES_FILE_PURPOSE, app.config["shares"])


@app.route("/secrets/<name>", method="POST")
def store_secret_metadata(name):
    """Records one of this host's own secrets (uuid/treshold/shares_saved)
    after secretweb_client.py has already published its shares to enough
    peers - not the shares themselves, just this host's own bookkeeping of
    what it has out on the network. Only this host's own local client can
    call this: _require_owner_matches_client_cert() is reused here against
    this server's own identity (from hosts.dta's "local" entry) rather
    than a caller-supplied owner field, so only a caller presenting this
    host's own certificate - i.e. nobody but this host's own CLI - ever
    satisfies it. Re-posting the same name overwrites (a new version of
    that secret), matching "latest version of SECRET_NAME" - no
    conflict-guard needed here the way /shares has one, since this is
    this host's own, self-managed list."""
    payload = bottle.request.json
    if not isinstance(payload, dict):
        bottle.abort(400, "body must be a JSON object")
    try:
        uuid = payload["uuid"]
        treshold = int(payload["treshold"])
        shares_saved = int(payload["shares_saved"])
    except (KeyError, TypeError, ValueError) as exc:
        bottle.abort(400, f"malformed secret metadata: {exc}")

    own_name = hosts_data.own_host_entry(app.config["hosts"])["name"]
    _require_owner_matches_client_cert(own_name)

    record = {
        "uuid": uuid,
        "treshold": treshold,
        "shares_saved": shares_saved,
        "last_updated": timeutils.utc_now_iso(),
    }
    app.config["secrets"]["secrets"][name] = record
    _persist_secrets()
    bottle.response.status = 201
    return record


@app.route("/secrets/<name>", method="GET")
def get_secret_metadata(name):
    """Returns this host's own recorded metadata for a secret it created
    (uuid/treshold/shares_saved/last_updated) - not the secret itself,
    just enough for secretweb_client.py's get-secret to know what to ask
    peers for. Same owner check as store_secret_metadata() - only this
    host's own local client can ever read it. This is also what resolves
    the "which host's version is current" trust question flagged in
    mynotes/Initials.txt for the decrypt flow: there's only ever one
    party this can be asked of (this host itself, via its own
    certificate), never a peer that could lie about it."""
    own_name = hosts_data.own_host_entry(app.config["hosts"])["name"]
    _require_owner_matches_client_cert(own_name)

    record = app.config["secrets"]["secrets"].get(name)
    if record is None:
        bottle.abort(404, "no secret recorded under this name")
    return record


def _persist_secrets() -> None:
    secrets_path = os.path.join(app.config["basedir"], "data", SECRETS_FILENAME)
    cryptofile.save(secrets_path, app.config["key1"], SECRETS_FILE_PURPOSE, app.config["secrets"])


class MTLSWSGIRefServer(bottle.WSGIRefServer):
    """bottle's WSGIRefServer wrapped in an SSLContext that requires and
    verifies a client certificate signed by ca_file (mutual TLS).

    If ready_sock is given, send_ready() is sent on it right after the
    listening port is bound (not merely after KEY1 is received) - that is
    the actual "server started successfully" signal the initiator waits
    on. Any failure up to and including the bind is reported back over
    the same socket via send_startup_error() before being re-raised.
    """

    def __init__(self, cert_file: str, key_file: str, ca_file: str, ready_sock=None, **kwargs):
        super().__init__(**kwargs)
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_file = ca_file
        self.ready_sock = ready_sock

    def run(self, app):
        from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
            context.load_verify_locations(cafile=self.ca_file)
            context.verify_mode = ssl.CERT_REQUIRED

            class MTLSServer(WSGIServer):
                def get_request(self):
                    conn, addr = super().get_request()
                    conn = context.wrap_socket(conn, server_side=True)
                    return conn, addr

            class MTLSRequestHandler(WSGIRequestHandler):
                """Exposes the already-verified client certificate (see
                MTLSServer above) to route handlers via
                bottle.request.environ["peercert"] - self.connection is the
                handshaked SSLSocket by the time a request is handled, so
                getpeercert() returns the parsed dict form (verification is
                mandatory: context.verify_mode is CERT_REQUIRED)."""

                def get_environ(self):
                    environ = super().get_environ()
                    environ["peercert"] = self.connection.getpeercert()
                    return environ

            handler_cls = self.options.get("handler_class", MTLSRequestHandler)
            self.srv = make_server(self.host, self.port, app, MTLSServer, handler_cls)
            self.port = self.srv.server_port
        except Exception as exc:
            if self.ready_sock is not None:
                key_handoff.send_startup_error(self.ready_sock, str(exc))
                self.ready_sock.close()
            raise

        if self.ready_sock is not None:
            key_handoff.send_ready(self.ready_sock)
            self.ready_sock.close()

        try:
            self.srv.serve_forever()
        except KeyboardInterrupt:
            self.srv.server_close()
            raise


def load_config(config_file: str) -> configparser.ConfigParser:
    """Reads config.ini."""
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def receive_key1_from_fd(key_fd: int) -> tuple:
    """Wraps the inherited socketpair fd and reads KEY1 off it, per the
    handoff protocol in key_handoff.py. The socket is returned open - the
    caller still owes the initiator a send_ready()/send_startup_error()
    once it knows whether startup actually succeeded."""
    sock = socket.fromfd(key_fd, socket.AF_UNIX, socket.SOCK_STREAM)
    return key_handoff.receive_key1(sock), sock


def _default_hosts_data(own_port: int) -> dict:
    """The initial content of hosts.dta on a host that has never seen the
    rest of the network yet: itself, as the only known host.

    address is this host's preferred/local address; all_addresses is the
    full list of addresses this host can be reached at and always
    includes address as one of its members - replication sends
    all_addresses, other hosts pick whichever they prefer to dial."""
    address = "127.0.0.1"
    return {
        "hosts": {
            socket.gethostname(): {
                "address": address,
                "all_addresses": [address],
                "port": own_port,
                "role": "server",
                "status": "local",
                "site": "",
                "online": "unknown",
                "last_updated": timeutils.utc_now_iso(),
            }
        }
    }


def _default_sites_data() -> dict:
    """sites.dta starts empty - sites are only ever added once hosts
    report where they physically are, there's no meaningful default."""
    return {"sites": {}}


def ensure_hosts_file(basedir: str, key1: str, own_port: int) -> dict:
    """Loads data/hosts.dta, creating it (plus its hosts.json mirror)
    with a single self-entry if it doesn't exist yet.

    Read fields with .get(name, default), not direct indexing - schema
    additions here should stay purely additive so older records loaded by
    newer code (or newer records loaded by not-yet-updated code) don't
    break on a missing field. See cryptofile.py."""
    data_dir = os.path.join(basedir, "data")
    return cryptofile.ensure_mirrored(
        data_dir, HOSTS_FILENAME, HOSTS_PLAINTEXT_FILENAME, key1, HOSTS_FILE_PURPOSE,
        lambda: _default_hosts_data(own_port),
    )


def ensure_sites_file(basedir: str, key1: str) -> dict:
    """Loads data/sites.dta, creating it (plus its sites.json mirror)
    empty if it doesn't exist yet. Same encrypted+plaintext-mirror
    mechanism as hosts.dta - see ensure_hosts_file()."""
    data_dir = os.path.join(basedir, "data")
    return cryptofile.ensure_mirrored(
        data_dir, SITES_FILENAME, SITES_PLAINTEXT_FILENAME, key1, SITES_FILE_PURPOSE,
        _default_sites_data,
    )


def _default_secrets_data() -> dict:
    """secrets.dta starts empty - this host's own secrets are only added
    once it actually creates or receives shares of one."""
    return {"secrets": {}}


def ensure_secrets_file(basedir: str, key1: str) -> dict:
    """Loads data/secrets.dta, creating it empty if it doesn't exist yet.
    Unlike hosts.dta/sites.dta, this file holds this host's own secret
    material and is never given a plaintext mirror - see cryptofile.ensure()."""
    secrets_path = os.path.join(basedir, "data", SECRETS_FILENAME)
    return cryptofile.ensure(secrets_path, key1, SECRETS_FILE_PURPOSE, _default_secrets_data)


def _default_shares_data() -> dict:
    """shares.dta starts empty - shares are only added as other hosts hand
    this host one of their secrets' shares to hold."""
    return {"shares": {}}


def ensure_shares_file(basedir: str, key1: str) -> dict:
    """Loads data/shares.dta, creating it empty if it doesn't exist yet.
    Holds shares this host is storing on behalf of other hosts' secrets -
    never given a plaintext mirror, same reasoning as secrets.dta."""
    shares_path = os.path.join(basedir, "data", SHARES_FILENAME)
    return cryptofile.ensure(shares_path, key1, SHARES_FILE_PURPOSE, _default_shares_data)


@contextlib.contextmanager
def _startup_guard(handoff_sock, description: str):
    """Reports any exception raised inside the block back to the
    initiator as a startup failure (see key_handoff.py) before letting it
    propagate, so a broken data file fails boot the same way a bad
    certificate or an unavailable port already does."""
    try:
        yield
    except Exception as exc:
        key_handoff.send_startup_error(handoff_sock, f"failed to initialize {description}: {exc}")
        handoff_sock.close()
        raise


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
    "--key-fd",
    type=int,
    required=True,
    help="File descriptor of the socketpair end KEY1 is received on.",
)
def main(basedir: str, config_file: str, key_fd: int) -> None:
    """Receives KEY1, ensures data/hosts.dta, data/sites.dta, data/secrets.dta
    and data/shares.dta exist (creating them if this is the host's first
    boot), then listens for mTLS connections and replies 200 OK once the
    client certificate has verified against ca.crt."""
    if config_file is None:
        config_file = os.path.join(basedir, "data", "config.ini")

    config = load_config(config_file)
    port = config.getint("secretweb", "server-port", fallback=59222)
    bind_address = config.get("secretweb", "bind-address", fallback="0.0.0.0")

    cert_dir = os.path.join(basedir, "certificates")
    cert_file = os.path.join(cert_dir, config.get("secretweb", "cert-file", fallback="cert.pem"))
    key_file = os.path.join(cert_dir, config.get("secretweb", "key-file", fallback="private.pem"))
    ca_file = os.path.join(cert_dir, config.get("secretweb", "ca-file", fallback="ca.crt"))

    key1, handoff_sock = receive_key1_from_fd(key_fd)
    app.config["basedir"] = basedir
    app.config["key1"] = key1

    with _startup_guard(handoff_sock, "hosts.dta"):
        app.config["hosts"] = ensure_hosts_file(basedir, key1, port)

    with _startup_guard(handoff_sock, "sites.dta"):
        app.config["sites"] = ensure_sites_file(basedir, key1)

    with _startup_guard(handoff_sock, "secrets.dta"):
        app.config["secrets"] = ensure_secrets_file(basedir, key1)

    with _startup_guard(handoff_sock, "shares.dta"):
        app.config["shares"] = ensure_shares_file(basedir, key1)

    server = MTLSWSGIRefServer(
        cert_file=cert_file,
        key_file=key_file,
        ca_file=ca_file,
        ready_sock=handoff_sock,
        host=bind_address,
        port=port,
    )
    bottle.run(app, server=server, quiet=True)


if __name__ == "__main__":
    main()
