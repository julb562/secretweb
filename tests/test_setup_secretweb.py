import configparser
import os
import shutil

import pytest

import setup_secretweb

TEST_CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def _config_with_cert_file(tmp_path, cert_filename, basename="cert.pem"):
    cert_dir = tmp_path / "certificates"
    cert_dir.mkdir()
    shutil.copy(os.path.join(TEST_CERTS_DIR, cert_filename), cert_dir / basename)

    config = configparser.ConfigParser()
    config["secretweb"] = {"cert-file": basename}
    return config


def test_shares_and_treshold_is_majority_of_other_hosts():
    other_hosts = [{"name": f"h{i}"} for i in range(5)]
    shares, treshold = setup_secretweb._shares_and_treshold(other_hosts)
    assert shares == 5
    assert treshold == 3


def test_shares_and_treshold_minimum_case():
    # _collect_hosts() enforces MIN_SERVERS=3 + MIN_CONTROLLERS=1, so
    # other_hosts is always >= 3 in practice - treshold must stay >= 2.
    other_hosts = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
    shares, treshold = setup_secretweb._shares_and_treshold(other_hosts)
    assert shares == 3
    assert treshold == 2


def test_own_hostname_from_cert_reads_bare_common_name(tmp_path):
    config = _config_with_cert_file(tmp_path, "good_client.crt")
    assert setup_secretweb._own_hostname_from_cert(str(tmp_path), config) == "good-client"


def test_own_hostname_from_cert_strips_domain(tmp_path):
    config = _config_with_cert_file(tmp_path, "domain_client.crt")
    assert setup_secretweb._own_hostname_from_cert(str(tmp_path), config) == "good-client"


def test_match_own_host_finds_bare_name_entry():
    hosts = [{"name": "good-client", "addresses": ["1.2.3.4"], "role": "server"}]
    assert setup_secretweb._match_own_host(hosts, "good-client") == "good-client"


def test_match_own_host_finds_domain_qualified_entry():
    hosts = [{"name": "good-client.example.org", "addresses": ["1.2.3.4"], "role": "server"}]
    assert setup_secretweb._match_own_host(hosts, "good-client") == "good-client.example.org"


def test_match_own_host_errors_clearly_when_nothing_matches():
    hosts = [{"name": "someone-else", "addresses": ["1.2.3.4"], "role": "server"}]
    with pytest.raises(SystemExit):
        setup_secretweb._match_own_host(hosts, "good-client")
