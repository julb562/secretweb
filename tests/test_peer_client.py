import os
import socket

import pytest

import peer_client
import shamir

TEST_CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

GOOD_CLIENT_CERT = os.path.join(TEST_CERTS_DIR, "good_client.crt")
GOOD_CLIENT_KEY = os.path.join(TEST_CERTS_DIR, "good_client.key")
OTHER_CLIENT_CERT = os.path.join(TEST_CERTS_DIR, "other_client.crt")
OTHER_CLIENT_KEY = os.path.join(TEST_CERTS_DIR, "other_client.key")
CA_FILE = os.path.join(TEST_CERTS_DIR, "ca.crt")


def _sample_share(owner="good-client", name="test-secret"):
    secret = shamir.ShamirSecret(name, owner, shares=5, treshold=3)
    secret.create_secret("hello world")
    return next(secret.iterate_participants())


def _store(port, share, cert_file=GOOD_CLIENT_CERT, key_file=GOOD_CLIENT_KEY):
    peer_client.store_share("127.0.0.1", port, cert_file, key_file, CA_FILE, share)


def _retrieve(port, share_uuid, cert_file=GOOD_CLIENT_CERT, key_file=GOOD_CLIENT_KEY):
    return peer_client.retrieve_share("127.0.0.1", port, cert_file, key_file, CA_FILE, share_uuid)


def test_store_then_retrieve_share_round_trips(spawned_server):
    port = spawned_server
    share = _sample_share()

    _store(port, share)
    result = _retrieve(port, share["uuid"])

    # keys are (x, y) tuples in `share` but come back as JSON arrays.
    assert result["keys"] == [list(point) for point in share["keys"]]
    assert {k: v for k, v in result.items() if k != "keys"} == {
        k: v for k, v in share.items() if k != "keys"
    }


def test_retrieve_unknown_uuid_raises_share_not_found(spawned_server):
    with pytest.raises(peer_client.ShareNotFoundError):
        _retrieve(spawned_server, "no-such-uuid")


def test_reposting_different_share_for_existing_uuid_raises_peer_request_error(spawned_server):
    port = spawned_server
    share = _sample_share()
    _store(port, share)

    conflicting = dict(share)
    conflicting["secret_hash"] = "0" * 64
    with pytest.raises(peer_client.PeerRequestError):
        _store(port, conflicting)


def test_retrieve_of_share_owned_by_someone_else_raises_peer_request_error(spawned_server):
    port = spawned_server
    share = _sample_share(owner="good-client")
    _store(port, share)

    with pytest.raises(peer_client.PeerRequestError):
        _retrieve(port, share["uuid"], OTHER_CLIENT_CERT, OTHER_CLIENT_KEY)


def test_is_reachable_true_for_running_server(spawned_server):
    assert peer_client.is_reachable(
        "127.0.0.1", spawned_server, GOOD_CLIENT_CERT, GOOD_CLIENT_KEY, CA_FILE,
    ) is True


def test_is_reachable_false_for_wrong_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]
    assert peer_client.is_reachable(
        "127.0.0.1", free_port, GOOD_CLIENT_CERT, GOOD_CLIENT_KEY, CA_FILE, timeout=1.0,
    ) is False
