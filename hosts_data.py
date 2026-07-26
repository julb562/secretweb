"""
Shared reads of the plaintext hosts.json mirror (see
server.ensure_hosts_file()) - "who am I" and "who do I trust" - used by
anything that needs the host list before it has KEY1 to decrypt hosts.dta
itself: initiator.py's boot-time key1 reconstruction, and
secretweb_client.py's peer discovery when creating a new secret.
"""
import json
import os

# Owned here (not server.py) specifically so server.py can import this
# module too, for the /secrets/<name> route's own-identity check, without
# a circular import - server.py re-exports this as server.HOSTS_PLAINTEXT_FILENAME
# for its existing consumers (setup_secretweb.py, tests, ...).
HOSTS_PLAINTEXT_FILENAME = "hosts.json"

UNTRUSTED_STATUSES = {"compromised", "deleted", "disappeared"}


class OwnHostNotFoundError(Exception):
    """No host in hosts.json has status 'local' - this host's own
    identity can't be determined."""


def load_hosts_json(basedir: str) -> dict:
    """Plain JSON read of the plaintext hosts.json mirror - no KEY1
    needed to read it, which is exactly why server.ensure_hosts_file()
    maintains that mirror in the first place."""
    path = os.path.join(basedir, "data", HOSTS_PLAINTEXT_FILENAME)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def own_host_entry(hosts_data: dict) -> dict:
    for name, record in hosts_data.get("hosts", {}).items():
        if record.get("status") == "local":
            return {"name": name, **record}
    raise OwnHostNotFoundError(
        "no host in hosts.json has status 'local' - can't determine this host's own identity"
    )


def trusted_peers(hosts_data: dict, own_name: str) -> list:
    peers = []
    for name, record in hosts_data.get("hosts", {}).items():
        if name == own_name or record.get("status") in UNTRUSTED_STATUSES:
            continue
        peers.append({"name": name, **record})
    return peers
