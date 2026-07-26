import pytest

import hosts_data


def test_own_host_entry_requires_a_local_status_host():
    with pytest.raises(hosts_data.OwnHostNotFoundError):
        hosts_data.own_host_entry({"hosts": {"a": {"status": "default"}}})


def test_own_host_entry_finds_the_local_one():
    hosts_json = {"hosts": {"a": {"status": "default"}, "b": {"status": "local"}}}
    assert hosts_data.own_host_entry(hosts_json) == {"name": "b", "status": "local"}


def test_trusted_peers_excludes_self_and_untrusted_statuses():
    hosts_json = {
        "hosts": {
            "me": {"status": "local"},
            "good": {"status": "default"},
            "bad": {"status": "compromised"},
            "gone": {"status": "deleted"},
        }
    }
    peers = hosts_data.trusted_peers(hosts_json, "me")
    assert {p["name"] for p in peers} == {"good"}
