"""
mTLS client for calling another host's server.py over the network -
currently just the share store/retrieve routes (see server.py's
/shares/<uuid> routes). More peer-to-peer request types (e.g. host-list
gossip) are expected to land here later; this is not the day-2
secret-creation/decryption CLI described in mynotes/Initials.txt, which
still needs to be built on top of this.
"""
import http.client
import json
import ssl

import click


class PeerRequestError(Exception):
    """A peer responded with an unexpected status, or the request failed."""


class ShareNotFoundError(Exception):
    """The peer has no share stored for the requested uuid."""


def _connect(
    address: str, port: int, cert_file: str, key_file: str, ca_file: str, timeout: float,
) -> http.client.HTTPSConnection:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=ca_file)
    # Hosts are identified by address in hosts.dta, not by a DNS name
    # verified against the server cert - identity is checked at the
    # application layer instead (see server._require_owner_matches_client_cert).
    ctx.check_hostname = False
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return http.client.HTTPSConnection(address, port, context=ctx, timeout=timeout)


def is_reachable(
    address: str, port: int, cert_file: str, key_file: str, ca_file: str, timeout: float = 3.0,
) -> bool:
    """Whether a peer's mTLS server answers - a GET to server.py's index
    route, which only replies once the TLS handshake (and thus this
    client's certificate) has verified. Connection/SSL/timeout failures
    mean "not reachable", not an error - that's exactly what's being
    asked here."""
    try:
        conn = _connect(address, port, cert_file, key_file, ca_file, timeout)
        try:
            conn.request("GET", "/")
            resp = conn.getresponse()
            resp.read()
            return resp.status == 200
        finally:
            conn.close()
    except (OSError, http.client.HTTPException):
        return False


def store_share(
    address: str,
    port: int,
    cert_file: str,
    key_file: str,
    ca_file: str,
    participant_data: dict,
    timeout: float = 10.0,
) -> None:
    """Sends one participant_data share (as yielded by
    shamir.ShamirSecret.iterate_participants()) to a peer host for it to
    store. Idempotent - re-sending the identical share is not an error."""
    share_uuid = participant_data["uuid"]
    body = json.dumps(participant_data).encode("utf-8")
    conn = _connect(address, port, cert_file, key_file, ca_file, timeout)
    try:
        conn.request(
            "POST", f"/shares/{share_uuid}",
            body=body, headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        resp_body = resp.read()
        if resp.status not in (200, 201):
            raise PeerRequestError(
                f"store_share failed: {resp.status} {resp.reason}: "
                f"{resp_body.decode('utf-8', 'replace')}"
            )
    finally:
        conn.close()


def retrieve_share(
    address: str,
    port: int,
    cert_file: str,
    key_file: str,
    ca_file: str,
    share_uuid: str,
    timeout: float = 10.0,
) -> dict:
    """Fetches a share this client previously had a peer host store, by
    uuid. Raises ShareNotFoundError if the peer has nothing stored for
    that uuid, and PeerRequestError for any other non-2xx response (e.g. a
    403 because the peer's owner-vs-certificate check rejected the request)."""
    conn = _connect(address, port, cert_file, key_file, ca_file, timeout)
    try:
        conn.request("GET", f"/shares/{share_uuid}")
        resp = conn.getresponse()
        resp_body = resp.read()
        if resp.status == 404:
            raise ShareNotFoundError(f"no share stored for uuid {share_uuid}")
        if resp.status != 200:
            raise PeerRequestError(
                f"retrieve_share failed: {resp.status} {resp.reason}: "
                f"{resp_body.decode('utf-8', 'replace')}"
            )
        return json.loads(resp_body)
    finally:
        conn.close()


@click.group()
def cli() -> None:
    """Manual/ops entry point for the store/retrieve-share routes."""


@cli.command("store-share")
@click.option("--host", required=True, help="Address of the peer host.")
@click.option("--port", type=int, required=True, help="Port of the peer host's server.")
@click.option(
    "--data-file",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="Path to a JSON file holding one participant_data share.",
)
@click.option("--cert-file", type=click.Path(exists=True, dir_okay=False), required=True)
@click.option("--key-file", type=click.Path(exists=True, dir_okay=False), required=True)
@click.option("--ca-file", type=click.Path(exists=True, dir_okay=False), required=True)
def store_share_cmd(host: str, port: int, data_file: str, cert_file: str, key_file: str, ca_file: str) -> None:
    """Sends a share to a peer host for it to store."""
    with open(data_file, "rb") as f:
        participant_data = json.load(f)
    store_share(host, port, cert_file, key_file, ca_file, participant_data)
    click.echo("status: OK - share stored")


@cli.command("get-share")
@click.option("--host", required=True, help="Address of the peer host.")
@click.option("--port", type=int, required=True, help="Port of the peer host's server.")
@click.option("--uuid", "share_uuid", required=True, help="uuid of the share to fetch.")
@click.option("--cert-file", type=click.Path(exists=True, dir_okay=False), required=True)
@click.option("--key-file", type=click.Path(exists=True, dir_okay=False), required=True)
@click.option("--ca-file", type=click.Path(exists=True, dir_okay=False), required=True)
def get_share_cmd(host: str, port: int, share_uuid: str, cert_file: str, key_file: str, ca_file: str) -> None:
    """Fetches a previously stored share back from a peer host, printing it as JSON."""
    participant_data = retrieve_share(host, port, cert_file, key_file, ca_file, share_uuid)
    click.echo(json.dumps(participant_data))


if __name__ == "__main__":
    cli()
