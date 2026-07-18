import itertools

import pytest

from shamir import (
    MAX_SECRET_BYTES,
    PRIME,
    InvalidShareError,
    ShamirSecret,
    ShareReconstructionError,
    integer_list_to_string,
    string_to_integers,
)


def _build_secret(secret_raw="correct horse battery staple", shares=5, treshold=3,
                   name="name", owner="owner"):
    dealer = ShamirSecret(name, owner, shares=shares, treshold=treshold)
    dealer.create_secret(secret_raw)
    return dealer, list(dealer.iterate_participants())


# ---------------------------------------------------------------------------
# string_to_integers / integer_list_to_string round trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("secret_raw", [
    "",
    "a",
    "hello world",
    "x" * 8,                                   # exactly one chunk
    "x" * 9,                                   # one chunk + 1 byte
    "x" * 16,                                  # exactly two chunks
    "\x00\x00\x00",                            # embedded null bytes
    "emoji test \U0001F600\U0001F4A9 unicode",  # multi-byte UTF-8
    "a" * 5000,
])
def test_string_integer_roundtrip(secret_raw):
    ints = string_to_integers(secret_raw, 8)
    assert integer_list_to_string(ints, 8) == secret_raw


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("shares,treshold", [
    (5, 1),   # every share would equal the secret in the clear
    (5, 0),
    (5, -1),
    (5, 6),   # treshold above shares
    (1, 2),
    (0, 2),
])
def test_constructor_rejects_invalid_treshold_shares(shares, treshold):
    with pytest.raises(ValueError):
        ShamirSecret("name", "owner", shares=shares, treshold=treshold)


@pytest.mark.parametrize("shares,treshold", [(2, 2), (5, 3), (10, 7), (3, 3)])
def test_constructor_accepts_valid_treshold_shares(shares, treshold):
    ShamirSecret("name", "owner", shares=shares, treshold=treshold)


# ---------------------------------------------------------------------------
# create_secret size cap
# ---------------------------------------------------------------------------

def test_create_secret_rejects_oversized_input():
    dealer = ShamirSecret("n", "o")
    with pytest.raises(ValueError):
        dealer.create_secret("a" * (MAX_SECRET_BYTES + 1))


def test_create_secret_accepts_boundary_size():
    dealer = ShamirSecret("n", "o")
    dealer.create_secret("a" * MAX_SECRET_BYTES)
    assert dealer.ready_to_decode


# ---------------------------------------------------------------------------
# End-to-end reconstruction
# ---------------------------------------------------------------------------

def test_exact_treshold_shares_decode_correctly():
    secret_raw = "correct horse battery staple"
    _, parts = _build_secret(secret_raw)
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    for p in parts[:3]:
        decoder.populate_decoder(p)
    assert decoder.decode() == secret_raw


def test_any_treshold_sized_subset_of_shares_decodes_correctly():
    secret_raw = "any subset of shares should work"
    shares, treshold = 6, 4
    _, parts = _build_secret(secret_raw, shares=shares, treshold=treshold)
    for combo in itertools.combinations(parts, treshold):  # all 15 subsets
        decoder = ShamirSecret("name", "owner", shares=shares, treshold=treshold)
        for p in combo:
            decoder.populate_decoder(p)
        assert decoder.decode() == secret_raw


def test_fewer_than_treshold_shares_cannot_decode():
    _, parts = _build_secret(shares=5, treshold=3)
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    for p in parts[:2]:
        decoder.populate_decoder(p)
    assert decoder.ready_to_decode is False
    assert decoder.decode() == ""


def test_populate_decoder_returns_correct_countdown():
    _, parts = _build_secret(shares=5, treshold=3)
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    assert decoder.populate_decoder(parts[0]) == -2
    assert decoder.populate_decoder(parts[1]) == -1
    assert decoder.populate_decoder(parts[2]) == 0
    assert decoder.ready_to_decode is True


def test_extra_shares_beyond_treshold_still_decode():
    secret_raw = "extra shares are harmless"
    _, parts = _build_secret(secret_raw, shares=5, treshold=3)
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    for p in parts:  # all 5, more than needed
        decoder.populate_decoder(p)
    assert decoder.decode() == secret_raw


def test_minimum_viable_scheme_two_of_two():
    secret_raw = "tight scheme"
    _, parts = _build_secret(secret_raw, shares=2, treshold=2)
    decoder = ShamirSecret("name", "owner", shares=2, treshold=2)
    decoder.populate_decoder(parts[0])
    assert decoder.ready_to_decode is False
    decoder.populate_decoder(parts[1])
    assert decoder.decode() == secret_raw


# ---------------------------------------------------------------------------
# InvalidShareError: malformed / out-of-range / duplicate shares
# ---------------------------------------------------------------------------

def test_rejects_duplicate_share_resubmission():
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    decoder.populate_decoder(parts[0])
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(parts[0])


def test_rejects_share_with_colliding_x_for_same_chunk():
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    decoder.populate_decoder(parts[0])
    forged = dict(parts[1])
    # reuse participant 0's x-coordinates with participant 1's y-values
    forged["keys"] = [
        (parts[0]["keys"][i][0], y) for i, (_, y) in enumerate(parts[1]["keys"])
    ]
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


@pytest.mark.parametrize("bad_keys", [
    None,
    [],
    "not-a-list",
    [(1, 2, 3)],     # wrong tuple arity
    [(1,)],          # wrong tuple arity
    [("x", 2)],      # non-int x
    [(1, "y")],      # non-int y
    [(0, 2)],        # x == 0 would leak the secret directly at that point
    [(-1, 2)],       # negative x
])
def test_rejects_malformed_or_out_of_range_keys(bad_keys):
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    forged = dict(parts[0])
    forged["keys"] = bad_keys
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


def test_rejects_x_at_or_above_prime():
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    forged = dict(parts[0])
    forged["keys"] = [(PRIME, y) for (_, y) in parts[0]["keys"]]
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


def test_rejects_keys_with_wrong_number_of_chunks():
    _, parts = _build_secret("a longer secret with multiple chunks of data")
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    decoder.populate_decoder(parts[0])
    forged = dict(parts[1])
    forged["keys"] = parts[1]["keys"][:-1]  # drop one chunk
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


# ---------------------------------------------------------------------------
# InvalidShareError: threshold/shares downgrade & type-confusion attacks
# ---------------------------------------------------------------------------

def test_rejects_treshold_downgrade_on_bootstrap_share():
    """A forged first share claiming treshold=1 must not be able to
    single-handedly reveal the secret."""
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    forged = dict(parts[0])
    forged["treshold"] = 1
    forged["shares"] = 1
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


def test_rejects_treshold_downgrade_on_subsequent_share():
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    decoder.populate_decoder(parts[0])
    forged = dict(parts[1])
    forged["treshold"] = 1
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


@pytest.mark.parametrize("field,value", [
    ("treshold", 0),
    ("treshold", -1),
    ("shares", 0),
    ("shares", 1),
])
def test_rejects_out_of_range_treshold_shares_values(field, value):
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    forged = dict(parts[0])
    forged[field] = value
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


def test_rejects_non_integer_treshold_or_shares():
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    forged = dict(parts[0])
    forged["treshold"] = "3"
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


def test_rejects_treshold_above_shares_in_submitted_share():
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    forged = dict(parts[0])
    forged["treshold"] = 6
    forged["shares"] = 5
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


# ---------------------------------------------------------------------------
# InvalidShareError: cross-secret / identity mismatches
# ---------------------------------------------------------------------------

def test_rejects_mismatched_uuid_between_shares():
    _, parts1 = _build_secret("secret one")
    _, parts2 = _build_secret("secret two")
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    decoder.populate_decoder(parts1[0])
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(parts2[1])


def test_rejects_mismatched_creation_date():
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    decoder.populate_decoder(parts[0])
    forged = dict(parts[1])
    forged["creation_date"] = "2000-01-01 00:00:00"
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


def test_rejects_mismatched_secret_hash():
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    decoder.populate_decoder(parts[0])
    forged = dict(parts[1])
    forged["secret_hash"] = "0" * 64
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


def test_rejects_mismatched_name_after_bootstrap():
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    decoder.populate_decoder(parts[0])
    forged = dict(parts[1])
    forged["name"] = "different name"
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(forged)


def test_bootstraps_identity_when_decoder_constructed_blank():
    """Documents current trust-on-first-use behavior: a decoder built
    without a known expected name/owner accepts whatever the first
    share claims."""
    _, parts = _build_secret(name="real-name", owner="real-owner")
    decoder = ShamirSecret("", "", shares=5, treshold=3)
    decoder.populate_decoder(parts[0])
    assert decoder.name == "real-name"
    assert decoder.owner == "real-owner"


def test_rejects_bootstrap_share_with_wrong_name_when_expected_declared():
    _, parts = _build_secret(name="real-name", owner="real-owner")
    decoder = ShamirSecret("expected-name", "real-owner", shares=5, treshold=3)
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(parts[0])


def test_rejects_bootstrap_share_with_wrong_owner_when_expected_declared():
    _, parts = _build_secret(name="real-name", owner="real-owner")
    decoder = ShamirSecret("real-name", "expected-owner", shares=5, treshold=3)
    with pytest.raises(InvalidShareError):
        decoder.populate_decoder(parts[0])


# ---------------------------------------------------------------------------
# ShareReconstructionError: tampering that passes populate_decoder but
# fails at reconstruction time
# ---------------------------------------------------------------------------

def test_tampered_y_value_caught_by_hash_check():
    _, parts = _build_secret()
    decoder = ShamirSecret("name", "owner", shares=5, treshold=3)
    tampered = dict(parts[0])
    tampered["keys"] = [(x, (y + 1) % PRIME) for (x, y) in parts[0]["keys"]]
    decoder.populate_decoder(tampered)
    decoder.populate_decoder(parts[1])
    decoder.populate_decoder(parts[2])
    with pytest.raises(ShareReconstructionError):
        decoder.decode()


def test_reconstruct_secret_raises_on_colliding_x():
    dealer, _ = _build_secret()
    with pytest.raises(ShareReconstructionError):
        dealer._reconstruct_secret([(5, 10), (5, 20), (7, 30)])


# ---------------------------------------------------------------------------
# Context manager reset
# ---------------------------------------------------------------------------

def test_context_manager_resets_state():
    with ShamirSecret("name", "owner", shares=5, treshold=3) as s:
        s.create_secret("inside the context")
        assert s.ready_to_decode is True
    assert s.ready_to_decode is False
    assert s.secret_matrix == []
    assert s.decoding_participants_keys == []


# ---------------------------------------------------------------------------
# Structural sanity of dealer output
# ---------------------------------------------------------------------------

def test_iterate_participants_yields_one_entry_per_share_with_all_chunks():
    secret_raw = "a secret long enough to span several eight byte chunks of data"
    shares, treshold = 5, 3
    _, parts = _build_secret(secret_raw, shares=shares, treshold=treshold)
    assert len(parts) == shares
    expected_chunks = len(string_to_integers(secret_raw, 8))
    for p in parts:
        assert len(p["keys"]) == expected_chunks
        assert p["treshold"] == treshold
        assert p["shares"] == shares
        assert p["secret_hash"] is not None


def test_participant_x_values_are_unique_within_a_chunk():
    _, parts = _build_secret(shares=8, treshold=3)
    for chunk_ind in range(len(parts[0]["keys"])):
        xs = [p["keys"][chunk_ind][0] for p in parts]
        assert len(xs) == len(set(xs))
