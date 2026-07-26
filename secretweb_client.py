"""
Day-2 CLI for creating a new secret across the network - the actual
end-user command described in mynotes/Initials.txt's "To create a new
secret to the network" section (steps 2.5-7): discover trusted peers from
hosts.json, Shamir-split the secret, send one share to each peer
(peer_client.store_share()), and - once enough peers have accepted it -
tell this host's own local server to record it as one of this host's own
secrets (peer_client.record_secret()).

Decrypting an existing secret is a separate, not-yet-built flow (see
mynotes/Initials.txt's "To de-encrypt a secret" section) - this only
covers creation.
"""
from __future__ import annotations

import configparser
import os
import sys

import click

import hosts_data
import peer_client
import shamir

DEFAULT_BASEDIR = os.path.dirname(os.path.abspath(__file__))


def _load_config(config_file: str) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read(config_file)
    return config


def _cert_paths(basedir: str, config: configparser.ConfigParser) -> tuple:
    cert_dir = os.path.join(basedir, "certificates")
    cert_file = os.path.join(cert_dir, config.get("secretweb", "cert-file", fallback="cert.pem"))
    key_file = os.path.join(cert_dir, config.get("secretweb", "key-file", fallback="private.pem"))
    ca_file = os.path.join(cert_dir, config.get("secretweb", "ca-file", fallback="ca.crt"))
    return cert_file, key_file, ca_file


def _shares_and_treshold(trusted_peer_count: int, shares: int | None, treshold: int | None) -> tuple:
    """Defaults: shares = every trusted peer, treshold = a simple
    majority - same formula used for KEY1 (see
    setup_secretweb._shares_and_treshold()). Both overridable via
    --shares/--treshold, validated so the CLI can't promise more shares
    than there are known trusted hosts to receive them."""
    if shares is None:
        shares = trusted_peer_count
    if treshold is None:
        treshold = shares // 2 + 1
    if shares > trusted_peer_count:
        raise click.ClickException(
            f"--shares {shares} exceeds the {trusted_peer_count} trusted peer(s) in hosts.json"
        )
    if not 2 <= treshold <= shares:
        raise click.ClickException(f"treshold ({treshold}) must be between 2 and shares ({shares})")
    return shares, treshold


@click.group()
def cli() -> None:
    """Day-2 client: create a new secret across the secretweb network."""


@cli.command("store-secret")
@click.option("--name", required=True, help="Name for this secret.")
@click.option(
    "--secret",
    default=None,
    help=(
        "The secret value. WARNING: visible to other local users via "
        "ps/proc while this command runs - prefer piping it via stdin "
        "instead (omit this option and pipe the value in)."
    ),
)
@click.option(
    "--shares", "shares_override", type=int, default=None,
    help="Override share count (default: every trusted peer in hosts.json).",
)
@click.option(
    "--treshold", "treshold_override", type=int, default=None,
    help="Override treshold (default: a simple majority of shares).",
)
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
def store_secret_cmd(
    name: str,
    secret: str | None,
    shares_override: int | None,
    treshold_override: int | None,
    basedir: str,
    config_file: str,
) -> None:
    """Shamir-splits a secret and publishes one share to every trusted
    peer, then records it as one of this host's own secrets once enough
    peers have accepted it - not before, so a partially-published secret
    never shows up as one of "this host's own secrets"."""
    if secret is None:
        secret = sys.stdin.read().removesuffix("\n")

    if config_file is None:
        config_file = os.path.join(basedir, "data", "config.ini")
    config = _load_config(config_file)
    cert_file, key_file, ca_file = _cert_paths(basedir, config)
    port = config.getint("secretweb", "server-port")

    hosts = hosts_data.load_hosts_json(basedir)
    own_host = hosts_data.own_host_entry(hosts)
    peers = hosts_data.trusted_peers(hosts, own_host["name"])
    if not peers:
        raise click.ClickException("no trusted peers in hosts.json to publish shares to")

    shares, treshold = _shares_and_treshold(len(peers), shares_override, treshold_override)

    secret_obj = shamir.ShamirSecret(name, own_host["name"], shares=shares, treshold=treshold)
    secret_obj.create_secret(secret)

    click.echo(f"Publishing '{name}' as {shares} share(s), treshold {treshold}...")
    successes = 0
    for peer, participant_data in zip(peers[:shares], secret_obj.iterate_participants()):
        try:
            peer_client.store_share(
                peer["address"], port, cert_file, key_file, ca_file, participant_data,
            )
        except (OSError, peer_client.PeerRequestError) as exc:
            click.echo(f"  {peer['name']}: FAILED ({exc})")
            continue
        click.echo(f"  {peer['name']}: OK")
        successes += 1

    if successes < treshold:
        click.echo("")
        click.echo(
            f"FAILED: only {successes}/{treshold} required shares were saved - "
            "this secret is not safely on the network and was not recorded locally."
        )
        raise SystemExit(1)

    try:
        record = peer_client.record_secret(
            "127.0.0.1", port, cert_file, key_file, ca_file,
            name, secret_obj.uuid, treshold, successes,
        )
    except (OSError, peer_client.PeerRequestError) as exc:
        click.echo("")
        click.echo(
            f"WARNING: shares were published to {successes}/{shares} peers (treshold met), "
            f"but recording this secret locally failed: {exc}"
        )
        click.echo(f"uuid {secret_obj.uuid} - you may need to record this manually.")
        raise SystemExit(1) from exc

    click.echo("")
    click.echo(
        f"OK - saved to {successes}/{shares} share(s) (treshold {treshold}) "
        f"at {record['last_updated']}. uuid {secret_obj.uuid}"
    )


if __name__ == "__main__":
    cli()
