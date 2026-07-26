# secretweb

A peer-distributed auto-unseal system: a mesh of mutually-trusting hosts
that hold Shamir shares of each other's disk-encryption keys (or any
other secret), so that a host can boot unattended, gather a threshold of
shares from its peers, and unseal itself - without a human operator and
without any single host (or its disk) ever holding a secret it can
decrypt alone. Conceptually a peer-to-peer variant of Vault's
auto-unseal, with trustee hosts standing in for a centralized unsealer.

## Status

Working, not production-hardened. The crypto core, storage format, boot
flow, and one full secret-creation flow are built and tested; several
pieces described in the original design notes (`mynotes/Initials.txt`)
are still stubs or entirely unbuilt - see **Relationship to
mynotes/Initials.txt** and the **Roadmap** below.

## Core idea, in one pass

1. Every host runs `server.py`, an mTLS-only service (mutual TLS - every
   connection, in both directions, presents a certificate signed by this
   network's own CA) holding a handful of encrypted-at-rest files: the
   host list, this host's own created secrets, and shares other hosts
   have handed it to hold.
2. `server.py` never touches disk in the clear and never receives its
   encryption key (`KEY1`) except once, at spawn time, over an inherited
   socket - never argv, never an environment variable, never a file (see
   `key_handoff.py`).
3. `initiator.py` is what actually gets `KEY1` to `server.py`: on a boot
   where this host has already been through first-time setup, it asks
   its trusted peers - in random order, retrying indefinitely - for
   shares of its own `KEY1` until it has enough to reconstruct it, then
   spawns `server.py` and exits. It is deliberately a single-shot
   process: nothing about key reconstruction stays resident in memory
   longer than it has to.
4. Creating a new secret (`secretweb_client.py store-secret`) works the
   same way in reverse: Shamir-split the secret, send one share to every
   trusted peer, and once enough of them confirm they've saved it, record
   it as one of this host's own secrets.

## Architecture

| File | Responsibility |
|---|---|
| `shamir.py` | Shamir secret sharing (split/reconstruct) - the only cryptographic primitive besides AES-GCM |
| `cryptofile.py` | Encrypted-at-rest JSON documents (AES-256-GCM, HKDF-derived per-purpose subkeys, atomic writes) |
| `key_handoff.py` | Wire protocol for handing `KEY1` from `initiator.py` to `server.py` over a socketpair, and reporting startup success/failure back |
| `hosts_data.py` | Reads the plaintext `hosts.json` mirror - "who am I," "who do I trust" - usable before `KEY1` is available to decrypt anything else |
| `server.py` | The long-running mTLS service: owns all encrypted data files, exposes `/shares/<uuid>` (store/retrieve a share handed to this host) and `/secrets/<name>` (record one of this host's own created secrets) |
| `initiator.py` | Boot-time: reconstructs `KEY1` from peer shares, spawns `server.py`, hands it `KEY1`. Also `--stop`, for systemd |
| `setup_secretweb.py` | One-time interactive bootstrap: collect the host list, generate `KEY1`, wait for peers, publish `KEY1` as shares, walk the operator through a manual, one-host-at-a-time handoff to the systemd-managed service |
| `peer_client.py` | Low-level mTLS client library for calling another host's `/shares`/`/secrets` routes - the building block, not the day-to-day tool |
| `secretweb_client.py` | The actual day-2 CLI: `store-secret` discovers trusted peers itself, Shamir-splits, publishes, and records - no manual host/cert bookkeeping |
| `timeutils.py` | UTC-only timestamp convention used for every stored/compared timestamp |
| `ansible/` | Deployment: parameterized roles installing production *and* test instances side by side on the same host(s), each with its own CA, systemd unit, and service user |

## Data model

All per-host state lives under `data/`, all of it AES-256-GCM encrypted
with `KEY1` except where noted:

- `hosts.dta` (+ plaintext `hosts.json` mirror - not sensitive, integrity
  only): the host list. Each entry has `address`/`all_addresses`, `port`,
  `role` (`server`/`controller` today), `status` (`local` for this host,
  `default`, or one of `compromised`/`deleted`/`disappeared` for hosts no
  longer trusted), `site`, `online`, `last_updated`.
- `sites.dta` (+ plaintext mirror): sites and their online status -
  present in the schema, not yet meaningfully used anywhere.
- `secrets.dta` (no plaintext mirror - sensitive): this host's *own*
  created secrets - `uuid`, `treshold`, `shares_saved`, `last_updated` per
  name. Never holds share contents, just bookkeeping.
- `shares.dta` (no plaintext mirror - sensitive): shares *other* hosts
  have asked this host to hold, keyed by uuid.
- `config.ini` (plaintext by design - see below): `server-port`,
  `bind-address`, cert/key/ca filenames, `initiated`, `systemd-unit-name`,
  and (once published) this host's own `key1-name`/`key1-uuid`/
  `key1-treshold`/`key1-shares` - the minimum a host needs to know, before
  it has `KEY1`, to ask the right peers for the right thing.

## Security model, briefly

- Every connection is mTLS; a request that reaches a route handler has
  already presented a certificate signed by this network's CA.
- That alone isn't authorization: `/shares` and `/secrets` additionally
  check that the *claimed owner* of a share/secret matches the connecting
  certificate's own identity (`server._require_owner_matches_client_cert`)
  - one trusted host can't store or retrieve another's data.
- `KEY1` never touches argv/env/disk in the clear on the receiving end;
  the CA private key is passphrase-encrypted, with the passphrase itself
  kept in an `ansible-vault`-encrypted file, never in plaintext in the repo.
- Production and test environments use entirely separate CAs - a test
  host's certificate cryptographically cannot authenticate to a
  production host, not merely "different port."

## Deployment

`ansible/site.yml` deploys **both** a production (`/opt/secretweb`) and a
test (`/opt/secretweb_test`) instance to every host in one run, each under
its own dedicated system user, with its own CA, port, and systemd unit -
`--tags prod`/`--tags test` selects one. See `ansible/roles/secretweb_app/
templates/howto.txt.j2` (deployed as `howto.txt` in each install) for the
actual day-to-day operator commands.

## Relationship to `mynotes/Initials.txt`

The original design notes are still the right mental model for the
overall shape, but a few specifics have been superseded by decisions made
while building this:

- **No local Unix-socket IPC between the CLI and the local service.** The
  notes envisioned the CLI asking "the local service" for the host list
  over a socket. In practice, `hosts_data.py` reads the plaintext
  `hosts.json` directly - simpler, and it's needed *before* `KEY1` is
  available anyway (boot-time reconstruction can't ask a service that
  isn't running yet for the list of who to ask). This local Unix-socket
  concept can be considered dropped, not just deferred.
- **The CLI talks to its own local server the same way it talks to
  peers** - a normal mTLS call to `127.0.0.1`, using this host's own
  certificate - rather than a separate local-only protocol.
- Housekeeping ("periodical cleaning, checks and updates to host-infos...
  we'll design more thoroughly later") was always deferred in the notes;
  it's now the largest block of unbuilt work - see **Roadmap**.
- Everything else - mTLS everywhere, single-shot client for key hygiene,
  threshold/shares derived from live trusted-host count, `key_handoff.py`'s
  socketpair handoff - was built as originally sketched.

## Roadmap

Decide-as-we-build items, grouped; nothing here is scheduled, this is
just organized for when we pick each one up.

### Client
- **`get-secret`** - the reverse of `store-secret`: ask trusted peers for
  shares of an existing secret by name/uuid and reconstruct it. The
  mirror image of a solved problem, but inherits a trust question already
  flagged in the original notes: asking a single host "what's the latest
  version of this name" lets a compromised host lie about it. Needs a
  decision (quorum agreement on the version pointer, or accept the risk
  given hosts are already trust-scored) before or as part of building it.

### Data model
- **`hosts.json`: add a `last_seen` field** (if not already present under
  another name) - groundwork for the housekeeper's polling below.

### Housekeeper (new)
A new long-running component - `mynotes`' "periodical cleaning, checks
and updates" - installed as its own systemd service, distinct from
`server.py`. Needs its own design pass on how it gets access to
`KEY1`/the encrypted stores (own key handoff? talks to `server.py`
locally?) before implementation starts. Scope so far:
- Poll other hosts' status (up/down, reachable).
- Keep `last_seen` current as it polls.
- Get-and-re-store a secret when the network changes - i.e. proactively
  re-share a secret when the trusted-host set it was split across has
  changed (a holder removed/compromised, a new host added). A real
  rotation operation - needs care around not leaking old shares and
  deciding what "the network changed enough to act" means.
- Report on overall network status.
- **Controller-specific:** push host-list data out to other hosts
  (replication/gossip), and track each host's "last updated host list"
  status - i.e. convergence tracking for that replication.

### Roles / topology
- **A third role: client-only** - alongside today's `server`/`controller`,
  a host that participates enough to *use* the network (create/read its
  own secrets) but never holds shares for anyone else.
- **A controller module**: add hosts, remove hosts, change a host's role
  or status - the actual admin/governance surface that
  `compromised`/`deleted`/`disappeared` statuses currently have no way to
  be set through.
- **Multi-controller consensus**: multiple controllers can exist, and
  must agree with each other *before* pushing an update out to the rest
  of the network - i.e. controllers can't unilaterally mutate the shared
  host list. The actual agreement mechanism (quorum vote? all-controllers
  required?) isn't designed yet.

### Setup / bootstrap
- **Read the initial host list from a file** instead of always typing it
  interactively - something Ansible can distribute alongside everything
  else it already templates (`config.ini`, certs), rather than requiring
  a human to type the same list into every host's terminal.

### Boot / startup
- **Accept `KEY1` directly as a startup parameter**, bypassing peer share
  collection - for scenarios like a network-wide power failure where no
  peers are up yet to ask. Cuts directly against the "`KEY1` never
  touches argv/env" principle `key_handoff.py` exists to uphold, so this
  needs a deliberately narrow, clearly-flagged escape hatch (e.g. an
  interactive-only prompt, never a CLI flag or env var) rather than a
  casual parameter.
