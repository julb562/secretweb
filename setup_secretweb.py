"""
Interactive bootstrap for a fresh secretweb network on this host.

Collects the full host list (this host and every other one - the same
list is expected to be entered on every host, in mirrored terminal
sessions; this host's own entry is found automatically afterward by
matching its certificate's Common Name, not by a special first prompt -
see _own_hostname_from_cert()), generates a fresh KEY1, writes
hosts.dta/sites.dta/secrets.dta, spawns server.py, waits for every other
host to come online, Shamir-splits KEY1 and publishes one share to each
other host, then walks the operator through a manual, one-host-at-a-time
hand-off to the real systemd-managed service - see
_manual_systemd_handoff() for why that stays manual and one-at-a-time
rather than automated.

Assumes certificates/ (cert.pem, private.pem, ca.crt) already exist,
provisioned externally (e.g. via ansible) - this script never touches them.
"""
import configparser
import datetime
import os
import secrets as secrets_module
import time

import click
from cryptography import x509
from cryptography.x509.oid import NameOID

import cryptofile
import initiator
import key_handoff
import peer_client
import server
import shamir
import timeutils

DEFAULT_BASEDIR = os.path.dirname(os.path.abspath(__file__))

MIN_SERVERS = 3
MIN_CONTROLLERS = 1
CONFIRM_PHRASE = "yes, erase everything"

POLL_INTERVAL_SECONDS = 10

DATA_FILENAMES = (
    server.HOSTS_FILENAME,
    server.HOSTS_PLAINTEXT_FILENAME,
    server.SITES_FILENAME,
    server.SITES_PLAINTEXT_FILENAME,
    server.SECRETS_FILENAME,
)


def _existing_data_files(data_dir: str) -> list:
    return [name for name in DATA_FILENAMES if os.path.exists(os.path.join(data_dir, name))]


def _confirm_destructive_reset(existing: list) -> None:
    click.echo("")
    click.echo("WARNING: existing secretweb data was found on this host:")
    for name in existing:
        click.echo(f"  - {name}")
    click.echo("")
    click.echo("Continuing will generate a brand new KEY1 and replace these files.")
    click.echo("The old files are renamed, not deleted - but without the old KEY1")
    click.echo("(which is never kept), they can never be decrypted again. Every host")
    click.echo("and secret this host currently knows about is effectively gone.")
    click.echo("")
    typed = click.prompt(f"Type '{CONFIRM_PHRASE}' to continue, or anything else to abort")
    if typed.strip() != CONFIRM_PHRASE:
        click.echo("Aborted - nothing was changed.")
        raise SystemExit(1)


def _stop_existing_server(basedir: str) -> None:
    """Stops a server left running for this basedir by a previous run of
    this script (or by initiator.py), via its pidfile - see
    initiator.stop_server(). A no-op if nothing is running."""
    if initiator.stop_server(basedir):
        click.echo("stopped a previously running server for this basedir.")


def _archive_path(path: str, suffix: str) -> str:
    candidate = f"{path}.old.{suffix}"
    counter = 1
    while os.path.exists(candidate):
        candidate = f"{path}.old.{suffix}-{counter}"
        counter += 1
    return candidate


def _archive_existing_files(data_dir: str, existing: list) -> None:
    suffix = datetime.datetime.now(datetime.timezone.utc).strftime("%y-%m-%d")
    for name in existing:
        path = os.path.join(data_dir, name)
        archived = _archive_path(path, suffix)
        os.rename(path, archived)
        click.echo(f"renamed {name} -> {os.path.basename(archived)}")


def _cert_paths(basedir: str, config: configparser.ConfigParser) -> tuple:
    cert_dir = os.path.join(basedir, "certificates")
    cert_file = os.path.join(cert_dir, config.get("secretweb", "cert-file", fallback="cert.pem"))
    key_file = os.path.join(cert_dir, config.get("secretweb", "key-file", fallback="private.pem"))
    ca_file = os.path.join(cert_dir, config.get("secretweb", "ca-file", fallback="ca.crt"))
    return cert_file, key_file, ca_file


def _own_hostname_from_cert(basedir: str, config: configparser.ConfigParser) -> str:
    """This host's identity, per its own certificate's CN (normalized the
    same way server.py normalizes a connecting peer's CN) - used instead
    of asking the operator to specially designate "this host" during
    collection, see _collect_hosts()/_match_own_host()."""
    cert_file, _, _ = _cert_paths(basedir, config)
    with open(cert_file, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return server.hostname_from_common_name(common_name)


def _prompt_addresses(label: str, default: str = "") -> list:
    while True:
        raw = click.prompt(f"Address(es) for {label} (comma-separated)", default=default)
        addresses = [a.strip() for a in raw.split(",") if a.strip()]
        if addresses:
            return addresses
        click.echo("at least one address is required")


def _prompt_role(label: str) -> str:
    return click.prompt(f"Role for {label}", type=click.Choice(["server", "controller"]))


def _prompt_host() -> dict:
    """One uniform prompt for every host, including this one - there's no
    special "self" prompt, since operators enter the same full list on
    every host's terminal (see module docstring) and this host's own
    entry is identified afterward via _match_own_host()."""
    name = click.prompt("Host name (leave blank to finish)", default="", show_default=False)
    if not name:
        return None
    addresses = _prompt_addresses(name)
    role = _prompt_role(name)
    return {"name": name, "addresses": addresses, "role": role}


def _tally(hosts: list) -> tuple:
    servers = sum(1 for h in hosts if h["role"] == "server")
    controllers = sum(1 for h in hosts if h["role"] == "controller")
    return servers, controllers


def _collect_hosts() -> list:
    click.echo("")
    click.echo(
        f"A minimum of {MIN_SERVERS} servers and {MIN_CONTROLLERS} controller "
        "is needed for the initial bootstrap to succeed. Enter every host in "
        "the network, including this one."
    )
    hosts = []
    while True:
        servers, controllers = _tally(hosts)
        click.echo(f"(so far: {servers} server(s), {controllers} controller(s))")
        minimum_met = servers >= MIN_SERVERS and controllers >= MIN_CONTROLLERS
        host = _prompt_host()
        if host is None:
            if minimum_met and hosts:
                return hosts
            click.echo(
                f"Need at least {MIN_SERVERS} servers and {MIN_CONTROLLERS} "
                "controller before finishing - a host is required"
            )
            continue
        hosts.append(host)


def _match_own_host(hosts: list, own_hostname: str) -> str:
    """Finds which collected host entry is this one, by matching its
    certificate-derived identity (see _own_hostname_from_cert()) against
    each entry's typed name, normalized the same way. Returns the entry's
    *typed* name (not the raw cert CN), so downstream data stays in
    whatever naming convention the operator used."""
    for host in hosts:
        if server.hostname_from_common_name(host["name"]) == own_hostname:
            return host["name"]
    click.echo("")
    click.echo(
        f"ERROR: this host's certificate identifies it as '{own_hostname}', "
        "which isn't in the list you just entered."
    )
    click.echo("Add it and run this script again.")
    raise SystemExit(1)


def _build_hosts_data(hosts: list, own_name: str, own_port: int) -> dict:
    records = {}
    for host in hosts:
        records[host["name"]] = {
            "address": host["addresses"][0],
            "all_addresses": host["addresses"],
            "port": own_port,
            "role": host["role"],
            "status": "local" if host["name"] == own_name else "default",
            "site": "",
            "online": "unknown",
            "last_updated": timeutils.utc_now_iso(),
        }
    return {"hosts": records}


def _load_or_default_config(config_file: str) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read(config_file)
    if not config.has_section("secretweb"):
        config.add_section("secretweb")
    section = config["secretweb"]
    section.setdefault("server-port", "59222")
    section.setdefault("bind-address", "0.0.0.0")
    section.setdefault("cert-file", "cert.pem")
    section.setdefault("key-file", "private.pem")
    section.setdefault("ca-file", "ca.crt")
    return config


def _shares_and_treshold(other_hosts: list) -> tuple:
    """shares = one per other host (self never holds a share of its own
    key1); treshold = a simple majority, so up to just under half of the
    other hosts can be down/compromised and key1 is still reconstructable.
    _collect_hosts() already enforces MIN_SERVERS + MIN_CONTROLLERS, so
    other_hosts is always >= 3, keeping treshold >= 2 - satisfying
    shamir.ShamirSecret's own validation automatically."""
    shares = len(other_hosts)
    treshold = shares // 2 + 1
    return shares, treshold


def _poll_for_hosts_online(
    basedir: str, hosts: list, own_name: str, config: configparser.ConfigParser,
) -> None:
    """Waits for every other host to be mTLS-reachable before it's safe to
    publish KEY1 shares to them. No bounded number of rounds - standing up
    a whole network can legitimately take hours; the operator decides
    when to give up, via Ctrl+C, not a timeout baked into this script."""
    other_hosts = [h for h in hosts if h["name"] != own_name]
    cert_file, key_file, ca_file = _cert_paths(basedir, config)
    port = config.getint("secretweb", "server-port")

    click.echo("")
    click.echo(f"Waiting for all {len(other_hosts)} other host(s) to come online (Ctrl+C to give up)...")
    remaining = {h["name"]: h for h in other_hosts}
    round_num = 0
    while remaining:
        round_num += 1
        for name in list(remaining):
            address = remaining[name]["addresses"][0]
            if peer_client.is_reachable(address, port, cert_file, key_file, ca_file):
                click.echo(f"  {name}: online")
                del remaining[name]
        if remaining:
            click.echo(f"  still waiting on: {', '.join(sorted(remaining))} (round {round_num})")
            time.sleep(POLL_INTERVAL_SECONDS)
    click.echo("all hosts online.")


def _publish_key1_to_network(
    basedir: str, key1: str, hosts: list, own_name: str, config: configparser.ConfigParser,
) -> tuple:
    """Shamir-splits key1 and sends one share to every other host - the
    same store-a-share mechanism any other secret will use. Unlike the
    more lenient general "create secret" flow (which only needs a
    minimum, not all, hosts to accept a share), this requires *all*
    stores to succeed: _poll_for_hosts_online() just confirmed every host
    reachable, so a failure here is a real problem worth stopping for, not
    something to silently tolerate for the network's single most
    foundational secret. Returns (uuid, treshold, shares) for main() to
    persist - see module docstring."""
    other_hosts = [h for h in hosts if h["name"] != own_name]
    shares, treshold = _shares_and_treshold(other_hosts)
    cert_file, key_file, ca_file = _cert_paths(basedir, config)
    port = config.getint("secretweb", "server-port")

    secret = shamir.ShamirSecret("key1", own_name, shares=shares, treshold=treshold)
    secret.create_secret(key1)

    click.echo("")
    click.echo(f"Publishing key1 as {shares} share(s), treshold {treshold}...")
    for host, participant_data in zip(other_hosts, secret.iterate_participants()):
        address = host["addresses"][0]
        try:
            peer_client.store_share(address, port, cert_file, key_file, ca_file, participant_data)
        except (OSError, peer_client.PeerRequestError) as exc:
            click.echo("")
            click.echo(f"ERROR: failed to publish key1 share to {host['name']}: {exc}")
            click.echo("Nothing more was published - fix the problem and rerun this script.")
            raise SystemExit(1) from exc
        click.echo(f"  stored on {host['name']}")

    click.echo("key1 published to the network.")
    return secret.uuid, treshold, shares


def _manual_systemd_handoff(basedir: str, config: configparser.ConfigParser) -> None:
    """key1 is safely on the network - this script's job is done. It
    cannot hand off to systemd itself (it runs unprivileged, as the
    secretweb/secretweb-test service user - systemctl needs root), so it
    explains what to do and gates on the operator confirming every OTHER
    host is safely in one of two states first: this host is about to go
    through a gap (temporary server stopped -> systemd server started)
    during which *its own* reconstruction (see initiator._collect_key1())
    depends on enough peers being reachable. If operators bounce multiple
    hosts through that gap at once, everyone's reconstruction can fail
    together - going one host at a time, confirming as you go, keeps at
    most one host ever in that gap."""
    unit_name = config.get("secretweb", "systemd-unit-name", fallback="secretweb")

    click.echo("")
    click.echo("key1 has been published to the network - this script's job here is done.")
    click.echo("")
    click.echo("What happens next matters for the REST of the network, not just this host:")
    click.echo("this host is about to go through a gap between the temporary server")
    click.echo("stopping and the real systemd-managed one starting - and when it starts,")
    click.echo("it reconstructs its own key1 by asking peers for shares back, which only")
    click.echo("works if enough of THEM are reachable at that moment. If multiple hosts")
    click.echo("go through this gap at once, everyone's reconstruction can fail together.")
    click.echo("")
    click.echo("So: go through hosts ONE AT A TIME. Before continuing here, every OTHER")
    click.echo("host in the network must be either still safely waiting in its own setup")
    click.echo("script (like this one), or already fully switched over to systemd.")
    click.echo("")
    while not click.confirm("Is every other host in one of those two states?"):
        click.echo("Take your time - check on the other hosts, then confirm here.")

    initiator.stop_server(basedir)
    click.echo("")
    click.echo("temporary server stopped.")
    click.echo(f"Now run:   sudo systemctl start {unit_name}")
    click.echo(f"Then confirm it's up:   sudo systemctl status {unit_name}")
    click.echo("Only once that's running should you move on to the next host.")


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
def main(basedir: str, config_file: str) -> None:
    """Interactively bootstraps a fresh secretweb network on this host."""
    data_dir = os.path.join(basedir, "data")
    os.makedirs(data_dir, exist_ok=True)
    if config_file is None:
        config_file = os.path.join(data_dir, "config.ini")

    existing = _existing_data_files(data_dir)
    if existing:
        _confirm_destructive_reset(existing)
        _stop_existing_server(basedir)
        _archive_existing_files(data_dir, existing)

    config = _load_or_default_config(config_file)
    own_hostname = _own_hostname_from_cert(basedir, config)
    click.echo("")
    click.echo(f"This host's certificate identifies it as: {own_hostname}")
    click.echo("Make sure to include it in the host list below.")

    hosts = _collect_hosts()
    own_name = _match_own_host(hosts, own_hostname)

    key1 = secrets_module.token_urlsafe(32)
    own_port = config.getint("secretweb", "server-port")

    hosts_data = _build_hosts_data(hosts, own_name, own_port)
    cryptofile.save_mirrored(
        data_dir, server.HOSTS_FILENAME, server.HOSTS_PLAINTEXT_FILENAME,
        key1, server.HOSTS_FILE_PURPOSE, hosts_data,
    )
    cryptofile.save_mirrored(
        data_dir, server.SITES_FILENAME, server.SITES_PLAINTEXT_FILENAME,
        key1, server.SITES_FILE_PURPOSE, {"sites": {}},
    )
    secrets_path = os.path.join(data_dir, server.SECRETS_FILENAME)
    cryptofile.save(secrets_path, key1, server.SECRETS_FILE_PURPOSE, {"secrets": {}})

    config["secretweb"]["initiated"] = "True"
    with open(config_file, "w", encoding="utf-8") as f:
        config.write(f)

    click.echo("")
    click.echo("data files written, starting server...")
    try:
        initiator.start_server(basedir, config_file, key1)
    except (OSError, key_handoff.ServerStartupError) as exc:
        click.echo(f"status: FAILED to start server: {exc}")
        raise SystemExit(1) from exc

    click.echo("server is running.")

    _poll_for_hosts_online(basedir, hosts, own_name, config)
    key1_uuid, key1_treshold, key1_shares = _publish_key1_to_network(
        basedir, key1, hosts, own_name, config,
    )

    config["secretweb"]["key1-name"] = "key1"
    config["secretweb"]["key1-uuid"] = key1_uuid
    config["secretweb"]["key1-treshold"] = str(key1_treshold)
    config["secretweb"]["key1-shares"] = str(key1_shares)
    with open(config_file, "w", encoding="utf-8") as f:
        config.write(f)

    _manual_systemd_handoff(basedir, config)


if __name__ == "__main__":
    main()
