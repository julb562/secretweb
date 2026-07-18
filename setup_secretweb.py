"""
Interactive bootstrap for a fresh secretweb network on this host.

Implemented: warn/confirm before wiping existing data, archive old data
files, generate a fresh KEY1, interactively collect the initial host
list (self + others, minimum 3 servers + 1 controller), write
hosts.dta/sites.dta/secrets.dta, and spawn server.py.

Not implemented yet (each stubbed below as a NotImplementedError, since
all three need the day-2 client script - the group-secretnet CLI that
talks to the local server over a Unix socket - which doesn't exist yet):
  1. Poll, via the client script, for the other bootstrapped hosts to
     come online.
  2. Once all required hosts are online, publish KEY1 to the network as
     Shamir shares via the client script - the same mechanism any other
     secret will use.
  3. Once KEY1 is safely on the network: stop the server spawned by this
     script, restart it as a properly managed systemd service (ansible
     will install that unit later), and exit.

Until those exist, this script stops after spawning the server and just
leaves it running in the foreground.

Assumes certificates/ (cert.pem, private.pem, ca.crt) already exist,
provisioned externally (e.g. via ansible) - this script never touches them.
"""
import configparser
import datetime
import os
import secrets as secrets_module
import socket

import click

import cryptofile
import initiator
import key_handoff
import server
import timeutils

DEFAULT_BASEDIR = os.path.dirname(os.path.abspath(__file__))

MIN_SERVERS = 3
MIN_CONTROLLERS = 1
CONFIRM_PHRASE = "yes, erase everything"

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
    """Placeholder. There's no PID file or SIGTERM handling yet, so this
    can't safely find-and-stop a running server automatically. Ansible
    will install this as a proper systemd service later, at which point
    this becomes `systemctl stop secretweb` (or similar) instead of a
    manual confirmation."""
    click.echo("")
    click.echo("NOTE: automatically stopping a running secretweb server isn't")
    click.echo("implemented yet. If one is already running for this basedir,")
    click.echo("stop it manually now before continuing.")
    click.confirm("Continue once you're sure nothing is running?", abort=True)


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


def _prompt_addresses(label: str, default: str = "") -> list:
    while True:
        raw = click.prompt(f"Address(es) for {label} (comma-separated)", default=default)
        addresses = [a.strip() for a in raw.split(",") if a.strip()]
        if addresses:
            return addresses
        click.echo("at least one address is required")


def _prompt_role(label: str) -> str:
    return click.prompt(f"Role for {label}", type=click.Choice(["server", "controller"]))


def _prompt_self_host() -> dict:
    click.echo("")
    click.echo("First, this host:")
    name = click.prompt("This host's name", default=socket.gethostname())
    addresses = _prompt_addresses(name, default="127.0.0.1")
    role = _prompt_role(name)
    return {"name": name, "addresses": addresses, "role": role}


def _prompt_other_host() -> dict:
    name = click.prompt("Other host's name (leave blank to finish)", default="", show_default=False)
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
        "is needed for the initial bootstrap to succeed."
    )
    hosts = [_prompt_self_host()]

    while True:
        servers, controllers = _tally(hosts)
        click.echo(f"(so far: {servers} server(s), {controllers} controller(s))")
        if servers >= MIN_SERVERS and controllers >= MIN_CONTROLLERS:
            other = _prompt_other_host()
            if other is None:
                return hosts
            hosts.append(other)
        else:
            click.echo(
                f"Need at least {MIN_SERVERS} servers and {MIN_CONTROLLERS} "
                "controller before finishing - add another host:"
            )
            other = _prompt_other_host()
            while other is None:
                click.echo("the minimum isn't met yet - a host is required")
                other = _prompt_other_host()
            hosts.append(other)


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


def _poll_for_hosts_online(basedir: str, hosts: list) -> None:
    """Not implemented yet: should use the day-2 client script to poll
    each of the other bootstrapped hosts until all are reachable/online,
    before it's safe to publish KEY1 to the network."""
    raise NotImplementedError(
        "polling for other hosts to come online is not implemented yet "
        "(needs the client script, which doesn't exist yet)"
    )


def _publish_key1_to_network(basedir: str, key1: str, hosts: list) -> None:
    """Not implemented yet: should use the day-2 client script to
    Shamir-split KEY1 and distribute shares to the other hosts - the
    same "create a secret" mechanism any other secret will use."""
    raise NotImplementedError(
        "publishing KEY1 to the network as shares is not implemented yet "
        "(needs the client script, which doesn't exist yet)"
    )


def _restart_via_systemd(basedir: str, proc) -> None:
    """Not implemented yet: once KEY1 is safely on the network, this
    should stop the server spawned directly by this script and restart
    it as a properly managed systemd service instead."""
    raise NotImplementedError(
        "handing off to the systemd-managed service is not implemented yet "
        "(needs the ansible/systemd integration, which comes later)"
    )


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

    hosts = _collect_hosts()
    own_name = hosts[0]["name"]

    key1 = secrets_module.token_urlsafe(32)

    config = _load_or_default_config(config_file)
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
        proc = initiator.start_server(basedir, config_file, key1)
    except (OSError, key_handoff.ServerStartupError) as exc:
        click.echo(f"status: FAILED to start server: {exc}")
        raise SystemExit(1) from exc

    click.echo("server is running.")

    try:
        _poll_for_hosts_online(basedir, hosts)
        _publish_key1_to_network(basedir, key1, hosts)
        _restart_via_systemd(basedir, proc)
    except NotImplementedError as exc:
        click.echo("")
        click.echo(f"NOTE: {exc}")
        click.echo("Stopping here for now - the server keeps running independently.")
        click.echo("Ctrl+C returns to the shell without stopping it.")
        try:
            proc.wait()
        except KeyboardInterrupt:
            click.echo("")
            click.echo("returning to shell - server process left running.")


if __name__ == "__main__":
    main()
