<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) as described in
[compatibility policy](docs/compatibility.md).

Release notes on GitHub are generated from commit subjects. This file is the other half: what changed
for somebody *running* Permguard — a setting that moved, an exit status that gained a meaning, a
default that is no longer the same. Nothing enforces it: write the bullets under *Unreleased* while
the change is fresh, and `scripts/prepare-release.sh` gives them their version number when a release
is cut.

## [Unreleased]

### Added

- **The Host listener: `admin.addr` serves the Host API.**
  The `admin` section, which was read and refused, is now the Host listener: `/host/v1` and `permguard.host.v1` on one port, over TLS, with `admin.tls` and `admin.allow` as before.
  It serves the grants: `GET` and `POST /host/v1/grants`, then the two-step `revoke/plan` and `revoke/run`.
  It serves the key rings (`GET /host/v1/keys`, and the public `GET /host/v1/keys/{ring}`), the lifecycle (`GET /host/v1/status`) and the effective configuration (`GET /host/v1/config/effective`).
  `GET /host/v1/config/effective` lists every setting the build reads with the value in force, its origin (`default`, `file`, `environment`, `command_line`) and its class: `startup` for what may differ between replicas sharing one file (binds, the volume and its directories, TLS files, key references, instance ids), `static` for the rest, the experimental switches included.
  `GET /host/v1/config/revisions` lists the changes the Host's dynamic journals recorded, newest first: the grant journal today.
  Every mutation carries a `request_id`; a retry inside ten minutes returns the stored answer, across a restart, from `host/state/replay/` on the volume.
  Every route decides with the Host's grants, under `authz.admin`, `lifecycle.read`, `keys.read`, `config.read` and `identity.read`.
  The last four operations are new to the grant registry.
  `admin.advertised_url`, optional, names where the listener is reached from outside; the keys redirect and `jwks_uri` use it while the listener serves plain TLS.
  The shipped development configurations bind it on `127.0.0.1:5444`; the container image exposes `5444`.

- **The Host guards its clock: `time.max_clock_skew`.**
  One time service now serves every Host path that reads the time: token expiry, grant expiry, the replay window, key rotation, and the `signed_at` of head statements and the gate on signing them.
  When the wall clock steps back by more than `time.max_clock_skew` (`PERMGUARD_TIME_MAX_CLOCK_SKEW`, default `30s`), the Host is in clock anomaly.
  In anomaly the Control Plane signs no NOTP head statement, since a verifier judges a head by its `signed_at`, and `GET /host/v1/status` lists `degraded: time` with the reason.
  Expiry keeps being judged at the time the clock was expected at, so setting the clock back never makes an expired token or grant valid again.
  The process stays ready: decisions, decision and event batches, and the audit trail keep going, ordered by sequence.
  The anomaly ends on its own once the wall clock passes the time it was expected at; opening and closing are audited as `host.clock_anomaly` and `host.clock_restored`.
  The highest wall time seen is kept in `host/state/CLOCK` on the volume, so a clock set back across a restart is caught at start.
  If that mark is itself wrong, left by a run under a clock set ahead, stop the server and remove `host/state/CLOCK`: the next start is a first start.
  A NOTP push or ref read that needs a fresh head statement during the anomaly is answered `503 unavailable`, to be retried.
  The OIDC key set's stale window is now measured in monotonic time, so a clock change neither shortens nor stretches it.

- **Subsystem layout migrations: `migrate status`, `recover`, `rollback` and `finalize`.**
  A subsystem laid out through the storage library keeps a manifest at `host/layout/<subsystem>/MANIFEST`, naming its layout version and generation directory.
  A migration runs offline, holding the volume: it writes an intent, builds the new generation beside the old one, verifies digests and counts, switches the manifest atomically and writes a commit.
  Evidence is carried byte for byte and never rewritten; a build that changes it, or writes into the old generation, is refused before the switch.
  The old generation stays after the commit until `migrate finalize`; `migrate rollback` returns to it, and refuses when the server has since written into the new generation.
  A server refuses to start while a migration is between two sides, and over a layout version or subsystem it does not read; `migrate recover` lands an interrupted migration on one side.
  The key rings are the first subsystems laid out this way: `keys-host-operations`, `keys-control-attest` and `keys-data-attest`.

- **One durability implementation.**
  Every store writes through the storage library: the decision spool, the event journals and indexes, the stream layout and signer manifests, the Control Plane's stores and cursor key, the Data Plane's temporal imports, the audit trail, the catalog and the key rings.
  No byte on disk changes: the formats are what they were, and existing volumes read as before.
  Every file the library replaces is created readable by its owner alone (`0600`), where it used to take the process umask: a backup or export user that read a state file, an index, a manifest or a key ring through a group permission now needs the owner's.
  The audit day seal, the private key files, a mirror's `IDENTITY` and `BLOCK`, a client store's refs and the server's key witness are written whole and flushed, where they used to be written in place: a crash no longer leaves a torn one.
  Where a store wrote a temporary and renamed it, flushed a segment or cut a torn tail by itself, the library now does it, with at least the flushes it had and the same fault handling everywhere.
  A structural check, `task check:durability`, reads every crate's syntax tree and fails on a durability primitive outside the library, however it is imported, aliased, pointed at or named inside a macro; the few uses it allows are listed with their reasons.

- **The audit engine: trails per class and resource under `host/audit/trails`.**
  Every audit record the server writes now lands in a trail of its class (`security`, `operations`, `access`) and its resource, `host/audit/trails/<class>/<SHA-256 of the resource>/`, one CBOR sequence per UTC day, each record chained to the one before it.
  Every action is registered with its class, its facts and its size; an unregistered action, an undeclared fact, a fact shaped like a token or a key, and a resource outside the action's root are refused before anything is written.
  A `security` record that cannot be written is answered as a failure to the code that recorded it.
  An `operations` record that cannot be written is counted and the Host reports `degraded: audit`; `access` records go through a bounded queue whose drops are counted and marked by an `audit.access_dropped` record in the trail that has the gap.
  With `audit.pseudonym` on, a principal is pseudonymised per resource: the Control Plane's and the Data Plane's trails do not correlate, but every tenant of one Plane shares its root until a Plane narrows its records to a tenant's resource.
  With it off, a principal is masked in the trail, as in every other sink.
  `access` and `operations` day files older than `audit.retention` are dropped; `security` ones are kept until checkpoints exist.
  The new trails carry no signed seal or checkpoint yet (WP-3.7), and `audit verify` does not read them yet.

- **Grant mutations are one transaction with their audit records.**
  Every grant issue, revocation plan and run, expiry and bootstrap — from the Host API, the offline `permguard host grants`, or the Host itself — is an operation of the security-mutation journal in `host/audit/mutations/`.
  Its intent is flushed first and recorded in the `security` audit trail, the grant is written carrying the operation id, the commit and its answer follow, and the outcome is recorded with the same operation id.
  A crash at any step is resolved at the next start: an operation the grant journal shows is committed and recorded as `reconciled`, one it does not show is marked failed.
  An outcome record a crash interrupts before it is marked written is written again at the next start, so the trail can hold it twice under the same operation id and phase.
  A request the grant store would refuse — an unregistered operation, a stale revision, a plan that does not match — is refused before the operation begins and leaves no audit record.
  A retry with the same request id inside ten minutes learns the committed answer, across a restart, after a crash too.
  A grant's revision is now compared under the journal's lock, so two concurrent writers cannot both win a race.
  A structural check, `task check:mutations`, reads every crate's syntax tree and fails on a write to the grant journal outside a function holding the engine's token, or on the token built anywhere but the engine.

- **The Host identity: `host/identity/` on the volume.**
  A Host now has a stable `host_id` (a UUIDv7, `urn:permguard:host:v1:<host_id>` as its subject), an identity key numbered by epoch, a signed identity document and a chain of succession records, and a fresh `boot_id` at every start, kept in `host/identity/BOOT`.
  `INIT` marks the installation as existing; with it on the volume, missing or damaged identity state refuses the start, and no replacement key is ever generated.
  A copied volume is the same Host with a new `boot_id`.
  Under the `development` profile the first start provisions the identity; from `production` up the server refuses to start until `permguard host identity provision --volume <path>` ran, which prints the external witness to keep outside the volume and give as `host.identity.witness`, required from `production` up and compared whenever it is set.
  `host.identity.suite` chooses the key's suite at provisioning: `pg-ed25519-sha256-v1` (the default) or `pg-p256-sha256-v1`.
  `GET /host/v1/identity` answers the document, the successions, the epoch-1 public key and the protocol versions under `identity.read`; `POST /host/v1/identity/rotate` rotates the key under the new operation `identity.admin`, as a security mutation; `permguard host identity show` and `rotate` do the same offline.
  Audit records now name the identity's `host_id` and `boot_id`; trails written before keep the volume id they named.

- **Peer Host sessions on `permguard.host.v1.IdentityService/PeerChannel`.**
  Two Hosts authenticate each other with a session proof bound to the TLS connection it runs on: each side presents its identity, the initiator sends `hello`, the responder a `challenge`, and each signs the transcript with its identity key.
  A session runs on one bidirectional gRPC stream over one TLS 1.3 connection with mutual TLS; a connection that changes between phases, or a channel relayed through a TLS-terminating proxy, fails the session.
  One connection carries one session; the stream stays open, each frame bounded to 512 KiB, until the peer closes it or it stays silent for 15 minutes.
  `POST /host/v1/sessions/hello` and `/prove` answer `503 peer_sessions_unserveable`: peer sessions are never separate requests.
  The peers a Host trusts are pinned in `host.peers` (`PERMGUARD_HOST_PEERS`), each `{host_id, fingerprint}` with the first fingerprint `permguard host identity show` prints; a peer no pin names is refused.
  The highest epoch a session was established at is kept per peer in `host/peers/<host_id>.cbor` on the volume: a peer presenting a lower epoch, or another key for an epoch already seen, is refused.
  `admin.peer_sessions` (`PERMGUARD_ADMIN_PEER_SESSIONS`) is `end_to_end`, the default on a listener with `admin.tls.client_ca`, or `disabled`, the default otherwise; a deployment behind a TLS-terminating proxy or sidecar states `disabled`.
  `GET /host/v1/status` and `/.well-known/server-configuration` publish `peer_sessions: {served, reason}`.
  Every session established or refused is a `host.session.established` or `host.session.refused` record in the security trail, and is counted in `permguard_host_peer_sessions_total`.
  No operation uses a session yet: memberships and their tasks come later, and a task message on an established session answers `not_served_yet`.

- **Secrets are witnessed, and zone keys are derived per zone, purpose and scope.**
  Every root a Host resolves is at least 32 bytes and is witnessed per reference and version in `host/state/witness/<reference>/<version>`, and per role and version in `host/state/witness/by-role/<role>/<version>`: other material under a version already seen refuses the start, whichever reference names it, and a new key takes a new version.
  Key versions are written `vN` (`v1`, `v2`, …); any other form is refused.
  `operations.secrets.coordinator_root_ref` (`PERMGUARD_SECRETS_COORDINATOR_ROOT_REF`) names the root this Host derives zone keys from, at `operations.secrets.zone_key_version` (`PERMGUARD_SECRETS_ZONE_KEY_VERSION`, default `v1`); the development provisioner generates it when it is named.
  Decision input tags are keyed per ledger, and decision subjects are pseudonymised per zone, under keys derived from it, so every replica of a zone writes the same tags and tokens without holding the zone's root; a member's delivered keys are kept in `host/zone-use/` and arrive with memberships.

- **The Host's key rings: `host/keys/<ring>`.**
  The operations ring (`host.operations`), the Control Plane's (`control.attest`) and the Data Plane's (`data.attest`) are kept by the Host under `host/keys/<ring>/`: a journal of every transition, `ring.cbor` rebuilt from it, `public/<thumbprint>.jwk` kept for good, and each private key in `private/<thumbprint>.key` (`0600`, the `custody.plaintext` relaxation until WP-3.2).
  A key is prepublished, active, retired-public or revoked; exactly one is active, the private half is destroyed as soon as the key stops signing and the signings in flight end, and a retired key stays in the published set for `operations.keys.retain`, then leaves it.
  Every published set has an epoch, rising at every change of the set, and a key-set digest; the Host identity signs a binding of each epoch (`permguard.host.ring-binding.v1`, valid 30 days, issued again before it ends).
  `GET /host/v1/keys/{ring}` answers the epoch, the digest and the binding; `GET /host/v1/ring-bindings` lists the bindings under `identity.read`; `host.identity` is listed too, the identity's current key, and is never in a Plane's key set.
  `POST /host/v1/keys/{ring}/rotate` prepublishes a successor, and `POST /host/v1/keys/{ring}/revoke/plan` then `revoke/run` revoke a key at once, with its reason and compromise time, under the new operation `keys.admin`, each a security mutation; `host.identity` rotates through `POST /host/v1/identity/rotate` only.
  Every transition is also a `host.keys.transition` record in the operations trail.

- **A verification bundle: `GET /host/v1/keys/bundle`.**
  Under `keys.read` on `resource` (`host`, `plane/<p>`, `plane/<p>/zone/<z>`, `plane/<p>/zone/<z>/ledger/<l>`), the Host answers, page by page, what a verifier needs to check its signatures without asking it again: the identity with its succession chain, every public key its rings published, every ring binding it issued and the revocations.
  The first page fixes a frontier, each ring's epoch and journal entry and the identity epoch, and signs the manifest once: a COSE_Sign1 `permguard.keys.bundle.v1` under the `host.operations` key active there, over the Host, the resource, the frontier, the item count, the bundle digest and `issued_at`.
  Later pages present that manifest as `frontier`, with `cursor`, and receive the same bytes: a rotation or a revocation in between changes nothing they carry, and a frontier the Host did not sign is refused; after an identity rotation it answers `409 frontier_unreproducible`.
  The items are canonical CBOR (`contracts/cbor/keys-bundle.json`), the same bytes over REST and `GetKeyBundle`.
  `permguard_host::keys::bundle::verify` checks a bundle offline from the identity's first fingerprint, the one `permguard host identity provision` printed: every ring must be bound at its frontier epoch by the current identity key, so a superseded identity key vouches for nothing; a key, a binding or a revocation outside the frontier is refused.
  Each ring now keeps every binding it issues in `host/keys/<ring>/bindings/<seq>.cose`, by its journal entry; a binding from before this version is issued again at the next start.
  A Host without `operations.keys` has nothing to sign the manifest, and answers `503`.

### Changed

- **`keys export --directory` reads a ring on the volume: `<volume>/host/keys/<ring>`.**
  The offline export answered that the build could not export a ring; it now reads the ring's journal on a stopped volume and prints its epoch, its key-set digest, `keys` (the JWKS of the published set the digest covers), `retained` (every other key it ever published, with its state) and `revoked` (the revocations); never a private key, and never a revoked key among `keys`.
  The directory is the ring's under `host/keys/`, no longer `<volume>/operations/keys`.

- **Ring keys are named `<ring>:<thumbprint>`, and the legacy key directories migrate once.**
  At the first start, the `ring.json` directory of each ring (`operations/keys/{operations,control,data}` on the volume, or the configured one) is migrated into `host/keys/<ring>` through the layout migration framework; its keys keep their material, and the old directory, with the private halves of the keys that had stopped signing, stays until `permguard migrate finalize --subsystem keys-<ring>` (`keys-host-operations`, `keys-control-attest`, `keys-data-attest`).
  A legacy directory outside the volume refuses the start.
  From the `production` profile upward the server does not migrate by itself: it refuses to start and names `permguard migrate keys --volume <dir> --backup <reference>`, run with the server stopped.
  New signatures name `<ring>:<thumbprint>`; Permguard's verifiers still accept an artifact naming the bare thumbprint of a key of the ring, so nothing signed before needs re-signing.
  A verifier outside Permguard that matches the `kid` exactly must accept both forms for artifacts signed before the upgrade.

- **A Plane signs payloads, never bytes.**
  The Host's signer handle signs a head statement, a decision batch or an event batch as its format writes it, and nothing else; a build composing its own Planes signs through `Signer<T>::sign(&payload)`, and a test signing with a ring of its own wraps it in `RingSigner`.
  `Payload` is sealed: the Host writes every signing input, the batch's protected header included, and a Plane hands it the batch's canonical bytes through `Jws::new`.

- **A key lifecycle covers the clock skew and the audit retention.**
  `operations.keys.publish_ahead` must be at least the key-set cache age (300 s) plus `time.max_clock_skew`, and outside development `operations.keys.retain` must be at least `audit.retention`, so a seal never outlives the published key that verifies it.

- **The decision log needs `operations.secrets.coordinator_root_ref`; `decisions.log.commitment` is retired.**
  A configuration still setting `decisions.log.commitment.key_ref` or `key_version` is refused with a message naming the new settings.
  The marker's `key_version` is the zone key version, and it never names two keys in one spool: a spool whose records already name the version under the commitment key of before refuses the start until `operations.secrets.zone_key_version` is raised (`v2` after `v1`), and `ZONE_KEYS` in the spool keeps the witness of each version's key.

- **Audit pseudonyms are derived per Host and resource: raise the key version.**
  The Host's trails, and the principals a sink renders, are pseudonymised under a key derived from the `audit.pseudonym` root for this Host and the resource, with the identifier's type and value in the MAC.
  The same root and version now give other tokens than before: the start is refused by the pseudonym witness until `operations.audit.pseudonym.key_version` is raised (`v2` after `v1`), so no version ever names two keys.
  Records written before keep the tokens they carry.

- **Read offsets are keyed per API, resource and Host: outstanding offsets are invalid once.**
  `CURSOR_KEY` in each store is now the root a cursor key is derived from, per API, resource and Host, and it is witnessed in `CURSOR_KEY.witness`: rotate by moving it to `CURSOR_KEY.previous` and writing a new one, or by removing it; other bytes written in place are refused.
  Offsets issued before this version are refused once; a consumer starts again from a fresh offset.

- **A Plane holds no secret: `Declaration::uses_secret` and `SecretHandle` are removed.**
  A Plane MACs only under the zone keys it declares (`Declaration::uses_zone_key`, `Registration::zone_key`), and `Host::register` takes the declaration alone.

- **Private keys are held by a custody: plaintext only under `development`.**
  `operations.keys.custody` (`PERMGUARD_KEYS_CUSTODY`) is `development`, `file`, `pkcs11` or `kms`; it defaults to `development` under the development profile and to `file` otherwise.
  `host.identity` and `host.operations` may take another with `operations.keys.rings."host.identity".custody` and `…"host.operations".custody`.
  `development` keeps PKCS#8 files in the clear, the `custody.plaintext` relaxation that discovery and `host status` publish and `production` and `regulated` refuse.
  `file` seals each private key at rest (`permguard.sealed-key.v1`): a fresh data key per key, wrapped by a key-encryption key, bound to the Host, ring, key and suite, so a blob copied under another key or to another Host does not open.
  The key-encryption key is `operations.keys.kek_ref` at `operations.keys.kek_version` (`vN`) in the secret store, exactly 32 bytes and witnessed like every root; `operations.keys.kek_provider` keeps it in a PKCS#11 token or the KMS instead.
  At the first start under `file`, keys found in plaintext (the identity's, the rings') are sealed in place; a start without its key-encryption key refuses and replaces nothing.
  To rotate the key-encryption key, set the new one and keep the old as `operations.keys.previous_kek_ref`/`previous_kek_version` for one start: every key's data key is rewrapped and its ciphertext is unchanged; then remove the previous one.
  `pkcs11` keeps keys non-extractable in a token (`operations.keys.pkcs11.module`, `token_label`, the PIN from `pin_ref`), in builds with the `pkcs11` feature; `kms` keeps them in Vault or OpenBao Transit (`operations.keys.kms.address`, `mount`, the token from `token_ref`, an optional `ca`).
  `data.attest` and `control.attest` sign while a request waits and are never on `kms`; `regulated` keeps `host.identity` and `host.operations` on `pkcs11` or `kms`.
  A `kms` key-encryption key is a Transit `aes256-gcm96` key created `derived`, without export or plaintext backup, and a `pkcs11` one a 256-bit AES key, always sensitive and never extractable: any other is refused at the start.
  A ring or identity on `pkcs11` or `kms` that still holds key files is refused: a key is never moved into a token or a KMS.
  Every seal and rewrap of a ring's key is a ring journal entry (`sealed`, `rewrapped`), written before the key is sealed, and an operations record; the identity's is an operations record.
  The start opens every key a ring signs with, so a key the key-encryption key does not open, or a public key that is not its private half's, fails the start rather than the first signature.
  The rings of a realm stay in plaintext on their directory manager, so a deployment with realms keeps the `custody.plaintext` relaxation.
  The offline `permguard host` commands take `--server-config <file>`, read it with the environment as the server does, and open, provision and rotate the identity through its custody; without it the custody is `development`, and `provision` prints the custody it used.

- **A security mutation is refused while the audit trail cannot record it.**
  A grant mutation whose intent record cannot be written applies nothing and answers `audit_unavailable` (503).
  One whose outcome record cannot be written stands and answers `mutation_unrecorded` (500); the record is written again before the next mutation and at the next start, and until it is, new grant mutations are refused and the Host reports `degraded: security_mutations`.
  A write to the mutation journal that fails stops it until the next start, which resolves what it left open; meanwhile a retry is answered `mutation_unrecorded` and new grant mutations `replay_unavailable`.
  The server starts all the same when the expiry of grants past their time cannot be written: such grants allow nothing either way.
  Reads and decisions are not affected.

- **A catalog or NOTP change whose audit record fails is no longer answered as a success.**
  The zone, ledger or push stands, as before, and the answer is `mutation_unrecorded` (500): read the state before retrying.
  It used to be a success with a warning in the log.
  A refusal whose record fails is still the refusal.

- **`audit.destination` no longer decides whether there is an audit trail.**
  The engine writes its trails on the volume whatever the setting; `tracing`, the default, also emits every record into the log stream, as before.
  `file` no longer writes the JSON-lines trail in `audit.directory`: trails written there before stay as they are, and `audit verify` still reads them.
  Those old trails are no longer sealed or swept by retention: nothing writes them any more.

- **A `PERMGUARD_*` environment variable no setting reads fails startup.**
  A typo or a retired name used to be ignored, so the default stayed in force without a word; the server now refuses to start and names the variable.
  `PERMGUARD_BUILD_*` and `PERMGUARD_COPYRIGHT_*`, read when the binary is built, are exempt, as are the experimental runtime switches and the settings a Plane declares.
  The variables the `environment` secret provider resolves pass too: anything under `secrets.env_prefix` (`PERMGUARD_SECRET_` by default) or under a realm's prefix.
  The CLI's own `PERMGUARD_*` variables and the installer's `PERMGUARD_VERIFY` are not server settings: exported where the server starts, they are refused.
  Variables the lab's compose file and Makefile interpolate on the host (`PERMGUARD_GRAFANA_PORT`, `PERMGUARD_CONTROL_HOST_IP` and the like) never reach the server container; exported in a shell that then runs the server directly, they are refused the same way.
- **`admin.addr` requires TLS, and a client CA unless it is a loopback bind in development.**
  A configuration that named `admin.addr` without `admin.tls` used to be refused because nothing served it; it is now refused because the Host listener never serves in the clear.
  A bind reachable from outside the host demands `admin.tls.client_ca` whatever `development_mode` says, where a loopback bind alone used to be enough.
- **`/server-host/keys` redirects once a Host listener a verifier can reach is configured.**
  With `admin.addr` set and no `admin.tls.client_ca`, the telemetry listener answers `308 Permanent Redirect` to the listener's `/host/v1/keys/host.operations`, at `admin.advertised_url` or `https://<admin.addr>`.
  The answer carries `Deprecation: true` (the HTTP Deprecation header in its draft form), and the process registry's `jwks_uri` names the new place.
  Behind mutual TLS, and without a Host listener, the route and the registry are unchanged: a verifier following `jwks_uri` holds no operator certificate.

- **Publishing an object needs a filesystem with hard links.**
  The Control Plane's ledgers, a Data Plane mirror and a CLI workspace publish objects by hard-linking a flushed temporary file to the object's name.
  The link is what makes the publish refuse to replace anything.
  A volume without hard links (FAT, exFAT, some network filesystems) now fails the publish with an error that says so, where it used to work without that guarantee.
- **Breaking for PEPs: an evaluation the plane could not perform is no longer a deny.**
  The native PDP answers it with the typed refusal `503`/`UNAVAILABLE`, class `unavailable`, code `evaluation_indeterminate`; a policy deny stays `200 {"decision": false}`.
  When an engine could not represent the request (a context, action or subject outside the partition's schema), the refusal is `400`/`INVALID_ARGUMENT`, class `validation`, code `evaluation_input_rejected` instead: sending it again cannot help.
  A batch with an indeterminate evaluation is refused whole, naming the evaluations that could not be evaluated; every evaluation it reached is still recorded.
  A deny that a `forbid` or a Rego `deny` rule determined stands beside another policy's failure in the same partition: `200 {"decision": false}` citing it, with the failure counted.
  The temporal PDP answers it `200` with `outcome: "indeterminate"`, no `decision`, `reason.code` `evaluation_indeterminate` and, per failed partition, one of `evaluation_deadline_exceeded`, `evaluation_panicked`, `evaluation_failed` or `evaluation_input_rejected` in place of the former `partition_failed` codes.
  Under minimal disclosure a temporal reason of an indeterminate result keeps its code and carries a fixed sentence instead of the engine's text.
  Decision records gain `outcome` (`permit`, `deny`, `deny_by_default`, `indeterminate`) beside `decision`, and an indeterminate record gains `causes`, the `evaluation_*` codes behind it; a record without them predates the members.
  `permguard_authz_decisions_total{outcome}` and `permguard_authz_evaluations_total{outcome}` gain the values `indeterminate` and `deny_by_default`, and `permguard_authz_partition_failures_total{reason}` counts failed partitions by cause, on the stateless and the temporal path.
  Every partition failure is logged as `authz.evaluation_failed` or `temporal.partition_failed` with its code, never the engine's text.
  `permguard test --remote` reads the refusal as the error a case may expect, and `permguard test` no longer reports a deny beside a failure as an error, so the two agree.
  `permguard decisions` shows and counts an indeterminate record apart from a deny, and `--decision indeterminate` selects it; `--decision deny` no longer includes it.
- **Breaking for dashboards and alerts: telemetry schema 2.**
  Metric labels now come from a closed registry, and no metric carries a zone, ledger, producer stream, instance, partition or realm as a label.
  `permguard_telemetry_schema_info{version="2"}` says which schema a process exposes.
  Counters and histograms keep their names and lose those labels; a label value outside its registered vocabulary is recorded as `other` and counted in `permguard_metric_label_values_refused_total`.
  Gauges that were set per ledger now read one aggregate: `permguard_sync_mirror_age_seconds` is the stalest mirror, `permguard_authz_blocked_ledgers` the number of blocked ledgers, `permguard_temporal_backlog_records`, `permguard_temporal_journal_bytes`, `permguard_temporal_import_gaps_open` and `permguard_gc_objects_retained` are totals, `permguard_temporal_import_staleness_seconds` the longest staleness and `permguard_temporal_last_shipped_seconds` the earliest last shipment.
  `permguard_keys_active` is labelled by `issuer` (`server` or `realm`) instead of the realm's name.
  Removed: `permguard_ledger_bytes`, `permguard_ledger_objects`, `permguard_ledger_counter`, `permguard_zone_bytes`, `permguard_zone_ledgers`, `permguard_sync_mirror_counter`, `permguard_sync_zone_ledgers`, `permguard_sync_zone_bytes`, `permguard_decisions_stream_acked` and `permguard_temporal_watermark`; `permguard_store_objects` is new.
  The bundled dashboards and the chart's alerts follow; a dashboard of your own that groups by `zone` or `ledger` needs the same change.
- Log records name zones and ledgers by their ids, never by their names, and no longer carry an occurrence's `event_id`, a partition's name or the detail of a refusal, which can repeat a profile the caller sent; the caller still receives the detail in the answer.
- Log records name a request only by an id the server drew, never by the `X-Request-Id` a client sent.
  The client's id is still echoed in `X-Request-Id`, and every answer also carries `X-Permguard-Request-Id`, the id the logs use.
- Log records are written by a background thread through a bounded queue: a stdout nobody drains drops records, counted in `permguard_log_lines_dropped_total`, and never delays a decision.
  Exported trace spans go through a bounded queue of 2 048 as well; a span dropped because the collector cannot keep up, or because its export failed, is counted in `permguard_trace_spans_dropped_total`.
- **Breaking for manifests that require Cedar `>=4.12.0`: Cedar's language version is now `4.11.0`, the version of the `cedar-policy` engine this build links.**
  It advertised `4.12.0`, a version its engine never implemented; every language now reads its engine's version and build from `Cargo.lock` at build time, so the two cannot drift.
  A manifest with a range such as `>=4.0.0` loads unchanged; decision-log epoch markers written from now on name Cedar `4.11.0`.
- Every language has a descriptor — its engine, what that engine can reach, the limits it enforces and where it runs — and a digest of it; a compiled partition is cached under its runtime's descriptor digest, so a build with another engine never serves a program compiled by a different one.
- **Operational: a compiled partition's cache footprint is now an estimate of what its engine keeps, not the size of its sources.**
  It is an order of magnitude larger for the same ledger, so the same `dataPlane.decisions.cache.bytes` holds fewer partitions; review the bound and the `permguard_authz_cache_bytes` gauge after upgrading.
- **Operational: the decision cache bounds each zone as well as the whole.**
  `dataPlane.decisions.cache.zone_partitions` and `zone_bytes` (`PERMGUARD_AUTHZ_CACHE_ZONE_PARTITIONS`, `PERMGUARD_AUTHZ_CACHE_ZONE_BYTES`) default to a quarter of the whole cache's bounds, but never below 4 partitions and 64 MiB unless the whole cache is smaller; a ledger's head is not counted against its zone.
  A deployment with a single zone therefore holds a quarter of the cache's partitions, not all of them: set the two keys to the whole cache's values to keep the previous behaviour.
  A zone over its bound evicts only its own entries, so one zone cannot empty the cache for the others; a bound larger than the whole cache is refused at startup.

### Security

- Releases are built, packaged and attested by one reusable workflow, `.github/workflows/release-build.yml`, which is the SLSA Build L3 builder their provenance names.
  Verify a release with `--signer-workflow permguard/permguard/.github/workflows/release-build.yml`; releases up to `0.1.6` keep `release-pipeline.yml`.
- A release is published only after the provenance of every file has been verified against this repository, the tag, the commit and the builder; images are verified as soon as they are pushed.
  The evidence is attached to the release as `provenance-files.txt` and `provenance-images.txt`.
- No job that compiles holds a secret or a token that can write; the policy engines are pinned exactly, built without their default features, and checked against the features Cargo resolves.
- Every release carries `reproducibility.txt`, the verdict of an independent rebuild of the Linux and Windows binaries compared with the published archives; a release claims to be reproducible only on `reproducible: yes`.
- The telemetry listener reports at startup when it is reachable beyond the host without TLS, naming the two ways to scope it.
- A panic in a policy engine is refused as the operation it came apart in, never as a crash or a `500` carrying the engine's own words: an evaluation is that partition's `evaluation_panicked` — wherever it ran, the first partition and the full queue's overflow on the calling thread included — an input check is `503 evaluation_indeterminate`, a compile or a validation of a policy or an artifact is refused at load or at push, and a temporal occurrence is that partition's failure.
- A Rego policy's `print(...)` no longer reaches the process's standard error: it could carry request data into logs past their field classification.
- Both planes and the CLI refuse to start when the languages this build carries collide: a duplicate language name, media type, artifact or input type, or a file-classification rule that cannot decide.
- A runtime can be evaluated in a supervised local worker — the same binary, started with a cleared environment under OS address-space, CPU and core-file limits, and killed at the decision's deadline — for engines whose work cannot be bounded in-process.
  The mechanism is in place; no runtime uses it yet.
- The server binaries report a panic by where it happened and withhold its message, which can carry policy text or tenant data.

### Fixed

- An object is never overwritten (H-06).
  The Control Plane's object store, a Data Plane mirror and a CLI workspace publish each object through one storage library, without replacement.
  Pushing the same object twice, at once or not, writes it once and rewrites nothing.
  A name already holding a different object is reported as corruption and left byte-for-byte as it was.
  A mirror's and a workspace's objects are now also flushed to disk, file and directory, before they count as stored.
- A commit no longer points a ref at objects that a power loss could take away.
  The objects negotiation told a push not to send may have been linked by another push that had not flushed them yet; their directories are now flushed before the ref is written.
- Two first pushes to a fresh ledger at once no longer collide on its `FORMAT` pin.
  Every replaced file is staged under its own random, exclusively created name, and a failed directory flush is reported instead of ignored.
  A push that finds objects stored by a concurrent first push reads the pin again before calling the ledger unversioned.
- A commit retried after its cached head statement was lost is answered with a statement signed again, where it used to carry an empty one the client could not verify.
- Temporary files a crash left behind are removed, and no longer counted as objects.
  The Control Plane's garbage collection removes those older than its grace period, and `permguard workspace objects prune` removes a workspace's.
- Canonical JSON follows RFC 8785 for every finite number: fractions and exponents are accepted and written as ECMAScript writes them (`1E30` as `1e+30`, `4.50` as `4.5`), where they used to be refused.
  An integer that does not read back as written, such as `9007199254740993`, is still refused, and integers already signed keep their bytes.
- Building a canonical CBOR map that names one key twice is refused instead of producing bytes no reader would accept.
- A temporal submission refused for a conflict answers gRPC `ABORTED`, as the temporal PDP contract requires, instead of `FAILED_PRECONDITION`; HTTP stays `409` and the class and code are unchanged.
- A `401` carries the `WWW-Authenticate: Mutual-TLS realm="permguard"` challenge, and an access denial's body is serialised rather than assembled, so no message can break its JSON.
- A gRPC call refused by a surface's peer allow list is answered in gRPC — `UNAUTHENTICATED` or `PERMISSION_DENIED`, with the code in `permguard-error-code` — rather than with an HTTP status and a JSON body.
- `checkout` towards another ledger no longer keeps the previous ledger's checkpoint. The
  checkpoint is kept per ref, and every ledger's default ref is `main`, so two ledgers checked out
  in turn shared one file: `status` reported the old counter, `plan` saw no changes, and a no-op
  `apply` reported a publication that never happened. The checkpoint now goes with the binding it
  belonged to.
- A boxcarred `check` now explains the batch's verdict. The top-level `context` used to be the
  first evaluation's, so an `execute_all` batch that ended in a deny answered `decision: false`
  beside `permitted by …`. The reason now names the evaluations that decided, the policies are the
  union of what they cited, and the batch carries no `id` of its own: the journal records one
  decision per evaluation, none for the batch.
- `checkout` and `pull` refuse a head that holds a partition the workspace's manifest does not
  declare, or a schema or artifact contract it does not declare for one it does, before writing a
  byte — naming what is missing and both ways out. Previously the files were written where no
  build reads them: the next `plan` would have deleted an undeclared partition from the ledger,
  and refused to build a partition holding a schema its manifest said it had none of.
- `check -f` now refuses `--subject`, `--action`, `--resource` and `--context` beside it instead
  of ignoring them in silence.
- `check` warns on stderr when the document names a zone or ledger other than the one the
  workspace or the flags resolved, and says how to send the document as written.
- `check` tells a deny the policies reached from a request they never saw: `evaluated` is `false`
  and `error` carries the reason when the plane could not evaluate the request. The exit status is
  unchanged — a deny is an answer either way.
- `check` names policies the way `test` does, by alias where the tracked head carries one, and
  keeps the identities in `policy_ids`, so a failed case and the decision it corresponds to share
  a name.
- `decisions list --since` is validated as RFC 3339 and normalised before it is compared. An
  empty string, a word or an epoch second used to be compared as text and exit 0 — matching
  everything, nothing, or ignoring the filter.
- `decisions list --limit N` returns N decisions. Marker events in the stream used to count
  against the limit, so `--limit 1` returned none.
- `remote add` refuses a name that already exists instead of replacing its URL and announcing
  "added".
- `remote remove` warns when the removed remote is the one the workspace tracks, and `status`
  shows the URL the CLI's fallback would use, marked as such, instead of "url unknown".
- `test` runs the case files it can read and reports the ones it cannot, instead of stopping at
  the first unreadable file — including a `--name` run aimed at another file. The run exits as not
  green while such a file is present; the file is not counted among the failed cases, because it
  is not one.
- `test --name` that matches nothing names the filter and how many cases it was applied to,
  instead of blaming a missing `tests` folder.
- `apply` with nothing to send no longer prints "Ref advanced" after "No changes".
- `apply -m ""` is refused: a commit message cannot be empty.
- `zones list` and `ledgers list` refuse `--size 0`, and `decisions list`, `events list` and
  `history` refuse `--limit 0`, where they are typed.
- `plan` says what it is — the working tree against the tracked head, offline — in its help and
  its "No changes" line, instead of claiming to have compared with the remote ledger.
- `decisions get` for an identifier that is not there says that a plane ships records in batches
  and the decision may not have arrived yet.
- `events list` on a plane that serves no event store names the two switches that gate it,
  instead of the bare `route_unknown`.
- `docker build` from a clean clone, or a clean BuildKit cache, no longer fails before compiling a
  line of Rust: the image installs `libprotobuf-dev` beside `protobuf-compiler`, because the
  well-known types `pdp.proto` imports ship in the -dev package on Debian.
- A failed `cargo build` inside the image is reported as itself. The build step joined its
  commands with `;`, so the `cp` of a binary that was never produced ran anyway and its error was
  the one BuildKit showed, with cargo's diagnostic scrolled away above it.
- Planes built by the compose lab reported an empty `version` and `commit`, in `permguard inspect`
  and on `/version`. The `Dockerfile` exports both stamps as empty strings when no build-arg names
  them, and the binary took an empty stamp for a stamp. Empty is now no stamp: the workspace
  version, and `unknown`.

### Changed

- Every timestamp the CLI emits in JSON and YAML is RFC 3339 in UTC. `history` (`author_at`),
  `objects cat --inspect` (`author_at`) and `zones`/`ledgers` (`created_at`, `updated_at`) used to
  emit epoch seconds while `inspect` and the decision log emitted RFC 3339.
- `check -o json`, `test -o json` and the catalog listings have one shape whatever the answer:
  `policies`, `evaluations` and `problems` are `[]` rather than absent; `id`, `reason`, `error`,
  `decision` and `page` are `null` rather than missing.
- `decisions list --limit` counts decisions, not records.
- `check -o json` inside a workspace names `policies` by alias where the tracked head carries one,
  as `test` does; the identities the plane cited are in `policy_ids`. Outside a workspace the two
  lists are the same.
- A boxcarred `check` answer carries no top-level `context.id`: the identifiers are on the
  evaluations, which are what the decision log records.
- Catalog pages count from 0, as every C-like interface counts: `zones list --page 0` and
  `ledgers list --page 0` are the first page, `?page=0` on HTTP likewise, and absent still means
  everything. On gRPC `page` and `size` carry presence (`optional`), which is what tells page 0
  apart from no page; a client built against the previous contract, which sent 0 for "not asked",
  still gets everything.
- A workspace is the manifest, the partitions it declares, `.permguardignore` and `.permguard/`,
  and nothing else. A file or folder the build does not know — at the root, or inside a partition
  with an extension no runtime reads — used to be skipped in silence; `validate`, `plan`, `apply`,
  `pull`, `checkout` and `test` now refuse it by name, with the three ways out: move it into a
  partition, remove it, or list it in `.permguardignore`. `documents.cedr` beside
  `documents.cedar` was a policy nobody enforced, and nothing said so.
- `checkout` of another ledger, or another ref, refuses while the tree holds changes not applied
  to the one it tracks — a checkout never carries work from one ledger into another, where the
  next `apply` would have published it under the wrong name. On a clean tree it now replaces the
  manifest and the partitions with the other ledger's, like `git checkout`; what
  `.permguardignore` names stays. Towards a ledger with no history yet the tree is emptied, and
  `init` gives the bound workspace a shape again. The first checkout after `init` is unchanged.
- A partition input is required unless the manifest says otherwise. `input: { type: … }` with
  no `required` used to mean `required: false`: a request that omitted the input was decided
  against an empty one, in silence. It now means `required: true`, and such a request is refused
  by name (`partition_input_required`). Fail-open is still available, written down: `required:
  false`. Every workspace in this repository already says which it wants.
- The empty input a request is decided against when it omits an optional one is validated against
  the partition's schema, exactly as the same input would be if stated. A Rego schema whose
  top-level `required` names a list therefore refuses a request that sends no document
  (`partition_input_schema`) instead of letting the rules read `{}` and never fire. Previously
  only a stated input reached the schema, so one document could pass by omission and fail by
  statement.
- Exit status `69` (`EX_UNAVAILABLE`): a plane that could not answer right now — unreachable, or
  refusing a ledger that has no history yet (`ledger_empty`) — used to exit `70` beside genuine
  internal failures, so a data plane still syncing a ledger read as the CLI being broken. `70` is
  now only a failure inside the CLI or the plane, and a script retries on `69`.
  `ledger_not_served`, a ledger this plane does not mirror, stays `64`.

### Added

- `init` and `clone` write a `.permguardignore` that excuses the usual neighbours of a workspace
  (`.git/`, `.gitignore`, `.gitattributes`, `.github/`, `README.md`, `requests/`, `tests/`). It
  reads like `.gitignore`: a name matches at any depth, a path with a `/` is a prefix from the
  root, a trailing `/` names a folder. An existing workspace that holds any of them lists them
  there once. What an operating system drops on its own — `.DS_Store`, `Thumbs.db`,
  `desktop.ini` — is never read and needs no entry.
- `validate` warns where a workspace is legal and fails open: a partition whose input is optional
  and whose Rego rules read `input.partition`, and one whose input is optional and whose schema
  refuses the empty input a request without one is decided against. The warnings are in the
  report (`warnings`, `[]` when there are none) and change nothing else; each says what to write
  to make the choice deliberate.
- A decision says which of the profile's declared inputs the request left out. The answer carries
  `context.absent_inputs`, the record `inputs.absent` (absent when every input arrived), `check`
  prints them beside the verdict and `decisions list` beside the policies — for an auditor, the
  difference between a guardrail that did not object and one that was given nothing to object
  with.
- `history --limit N`: at most N commits, newest first.
- `check` answers carry `evaluated`, `error` and `policy_ids`; `test` and `test --list` carry
  `unreadable`; `status` carries `remote_configured`.
- `pull` now lands the incoming head in the working tree instead of only creating the files that
  were missing. A policy the remote moved and the author had not is advanced inside the author's
  file, whatever name that file has and whatever else it holds; a policy the remote dropped and the
  author had not touched is removed, and its file with it once nothing else is left in it; a policy
  both sides moved is a conflict, and the pull refuses without advancing the checkpoint or writing
  anything. The pull refuses the same way when the remote adds a policy whose file name this
  workspace already uses for something else, and when the working tree does not build. Previously
  the checkpoint moved while the tree kept the old content, so the next `apply` — which diffs the
  tree against the checkpoint — silently reverted the other author's commit and reported success.
  The refusal names each file and the object to read it with (`permguard objects cat <digest>`);
  `pull --resolved` accepts the working tree as already reconciled and advances.
- `pull`, `checkout` and `clone` now count what they advanced and removed alongside what they
  wrote. "0 files written" alone read like a no-op on a pull that changed content. `pull` also
  says `Already up to date.` only when it truly had nothing to do: a refused pull leaves its
  objects in the local store, so the `--resolved` retry fetches none and still moves the ref.
- Event and decision ingest now validates signer-manifest changes before replacing any retained
  envelope or record. Reusing one `kid` with different key material is refused without changing
  the acknowledged evidence.
- Signer discovery no longer sorts the complete on-disk stream tree on every request, and signer
  ranges have a fixed response ceiling. Cursors are complete, canonical triples on REST, gRPC, and
  the CLI.
- Concurrent stream-layout claims cannot overwrite a version marker another process published;
  uncommitted key-archive staging files are ignored while malformed committed keys still fail
  closed.
- The standalone experimental control-plane configuration now declares the exact decision
  producer it accepts, so the documented paired-plane command passes startup preflight.

## [0.1.6] - 2026-08-30

### Added

- **A second decision interface: `permguard.api.pdp.temporal.v1alpha1`.** The one Permguard has
  always served answers *may this subject do this to this?* from the request. This one answers *may
  this happen, given what has happened?* — from the request **and** a durable history. An occurrence
  is submitted to `POST /temporal/v1alpha1/events` (or `TemporalPolicyDecisionPoint.SubmitEvent`),
  made durable, observed, and then decided; a history-only kind returns a receipt with **no
  `decision` field at all**, because a fabricated verdict a caller cannot tell from a decided one is
  the most dangerous thing such an interface could return. Off unless a deployment enables it.

- **Dogwood as a policy runtime**, through Amazon's `amzn-dogwood-language` at a reviewed immutable
  revision. Cedar plus history: a policy may ask what has happened recently as well as what is being
  asked now. Permguard supplies what a production deployment needs around it — the durable journal,
  provenance, replication, limits, and the failure modes upstream's reference interpreter documents
  as out of scope.

- **`permguard events list|tail|get|export|verify`**, reading from the control plane's event store.
  `export` fixes a snapshot from its first page and terminates on a ledger that is still recording;
  `verify` checks each record against its inclusion path and, with `--keys`, the signature over the
  batch — and says which of the two it did.

- **Bounded temporal evaluation.** Deciding against a history no longer means reading one: the
  journal keeps a rebuildable index beside its segments, and a decision range-scans it for one
  history partition over one time window. Each history partition has its own engine, kept in a
  bounded least-recently-used set; eviction costs a replay from the durable record and never an
  answer. `max_window` is a ceiling, not a reason to read everything under it.

- **`/.well-known/permguard-events-native-v1alpha1-configuration`**, and
  `EventLog.GetEventConfiguration` beside it: where batches go, which event types are accepted, and
  how read offsets are spelled — so a producer is configured with one URL rather than a runbook.

- **`config.local-experimental.yml` beside each server crate**, with `task run:experimental`,
  `make run-experimental` and `task cp-dogwood`: a working deployment with every experimental
  runtime this build carries turned on — today that is Dogwood and the event path it needs.

- **`experimental.<name>.enabled`**, one key per provisional runtime rather than a flag per
  language. A language declares itself experimental and the gate iterates, so a runtime added or
  graduated needs no change to the configuration types, the file schema or the composition roots.
  Naming a runtime this build does not gate is refused at startup instead of doing nothing.

- **`bench/temporal.js`**, measuring what an occurrence costs — recorded, decided, and under overlap.

- **A control-plane event store**: signed batch ingest, tenant-isolated reads, a bounded per-type
  index so listing one event type does not scan the rest, and retention that removes whole sealed
  segments while keeping the envelopes and archived keys that prove what stays.

### Changed - breaking, pre-release

- **Ports now identify server roles independently of transport security.** Server Host operations
  use `5443`, the Control Plane uses `6443`, the Data Plane uses `7443`, and `8443` is assigned to
  the Trust Plane. HTTP and HTTPS use the same role port; the scheme selects transport security.
  Every shipped configuration, client default, container, Helm workload, example, and discovery
  document now follows this convention. Standalone Server Hosts sharing a machine need distinct IP
  addresses or network namespaces rather than a different role port. The shipped mTLS profiles now
  multiplex HTTP and gRPC on the role port with one mutual-TLS policy, so both transports require a
  trusted client certificate instead of silently creating `7557/7657` side ports.

- **`permguard.pdp.v1` is now `permguard.api.pdp.native.v1`.** The old name says which product the
  interface belongs to; the new one says which of the two interfaces it *is*. A manifest that still
  writes the old name loads and is served identically — there is one contract and one legacy
  spelling of its name — but nothing generates it any more: the CLI writes the new name, the
  discovery documents advertise it, and the shipped examples carry it.

- **Read offsets are signed.** A decision-log offset used to be base64 JSON a consumer could edit:
  it could move itself to a position it was never given, present an offset issued for one tenant
  under another, or widen a filter after the fact. The API family, the scope, the normalized filters
  and the export bound are now inside a MAC, and presenting an offset under any of them changed is a
  stable refusal rather than a reinterpretation. **Outstanding offsets are invalidated by this
  change**; consumers resume from `oldest_available` or from the beginning.

- **Reads are bounded by bytes as well as records,** and report `oldest_available`,
  `high_watermark` and `coverage`. A record count alone does not bound a response. `permguard
  decisions export` now fixes a snapshot and terminates instead of chasing a moving end.

- **The event interfaces take two switches.** `dataPlane.events.enabled` and
  `controlPlane.events.enabled` now also require `experimental.dogwood.enabled`: one is a statement
  about disks, the other about accepting a contract whose shape is not yet stable. A plane that has
  said one and not the other refuses to start rather than serving an interface nobody can reach.

- **A temporal partition declares its history scope.** A schema with no universal symmetric pin
  ranges over the whole retained ledger on every evaluation, and that is now accepted out loud —
  `history: { scope: global }` — or refused. Declaring it on a partition that *is* pinned, or on a
  runtime that keeps no history, is refused too.

- **A partition declares typed artifacts.** `schema: true` remains valid for Cedar and Rego and
  means what it always did; a runtime that needs several distinct artifacts — Dogwood needs an
  action schema, and may need an event schema, macros and provider programs — declares them by
  registered name under `artifacts:`. The authoring walk and the plane's loader both ask the
  registry, so neither carries a switch that mentions a language.

### Fixed

- **A Rego partition attributed a decision to every policy sharing a package.** Two policies in one
  package produced a decision citing both, so an audit trail said a rule had decided when it had
  not. Two policies claiming one package are now refused at load, by name: a package is a namespace,
  and two files claiming it are two authors who each believe they own it.

- **The stateless request now refuses a field it does not know.** A misspelt member used to parse
  and be dropped — `"contxt"` beside `"subject"` produced a decision made *without* the context the
  caller believed it had sent, and the answer looked exactly like a correct one. Every level of the
  request is strict now; responses stay lenient, because that direction really is the reader's duty.

- **A gRPC number that is not a number is refused rather than becoming `null`.** `NaN`, infinity and
  a value with no `kind` all converted to JSON `null`, which is a *value a policy can test* — so a
  malformed request quietly became a well-formed one saying something else. The numeric domain is
  now stated and enforced, and `null` is spelled `NullValue`.

- **The gRPC client sent every request as a batch.** A single evaluation went over `EvaluateMany`,
  so the boxcarring semantics applied to a request that had not asked for them. It now picks by
  whether `evaluations` is non-empty.

- **A thread that failed to start was counted as one that ran.** The parallel evaluator ignored
  spawn failures, so a partition could be silently skipped and its `forbid` never seen. Started
  workers are counted, a shortfall is reported, and a fan-out with no workers runs locally.

- **A restarted plane could not reopen its own event journal.** The stream identity was compared
  including the producer *instance*, which is minted per process — so every restart was refused as
  somebody else's stream. The comparison is now over what identifies the chain; the instance is
  adopted from the recovered state, which is what continuing a chain means.

- **A restarted plane decided against an empty history.** The journal is durable and the engine that
  reads it starts empty, so every decision after a restart — or after a cache eviction — ranged over
  nothing, returning a `deny` indistinguishable from a correct one. A cold history is now replayed
  from the durable record before it decides.

- **A shared-mode rebuild discarded the plane's own history.** Absorbing imported events replayed
  only the imported half, silently dropping everything the plane had recorded itself. Local and
  imported records are now merged into one ordered run.

- **Two requests arriving on a cold ledger compiled it twice.** Reading a manifest and compiling a
  policy set are idempotent and expensive; without a gate, every request arriving while the first
  was compiling repeated the work and threw it away — a stampede at every restart, commit change and
  cache eviction. One caller now does the work and the rest wait for it, per key.

- **Loading a ledger blocked an async worker thread.** Reading, decoding and compiling now happen on
  a blocking thread, and the decision budget is measured from the start of the whole decision rather
  than from after the load it was meant to bound.

- **A commented example in a shipped configuration could not be used.** The `events` blocks sat
  under `log:`, so uncommenting them produced a file the plane refuses. Every example now lives
  under the section whose settings it shows, and a test uncomments each one and starts it.

- **`events.stream.group_commit_max_delay` did nothing.** It was read and never used: every
  submission paid for its own `fsync`. Overlapping submissions now share one.

- **`schema: false` declared nothing, and now does.** A partition with the flag off was treated as
  declaring an *optional* schema rather than none, so a schema file sitting beside it was accepted
  in silence — by the CLI at authoring and by the plane at load. Both now refuse it, which is what
  the flag has always meant.

## [0.1.5] - 2026-08-28

### Changed — breaking, pre-release

- **A plane publishes where it is reached, not where it binds.** `public.http.advertised_url` is
  the address the discovery documents name; absent, the bind address is used as before. This was a
  real defect on Kubernetes: a pod binds `0.0.0.0` because it has to, and every document this
  deployment served named `http://0.0.0.0:7443` — an address a listener understands and nothing can
  dial. The chart now sets it to the Service DNS by default and takes an override for an Ingress or
  a load balancer. A plane that binds a wildcard and was told nothing to advertise warns at
  startup, beside the line that says where it is listening.

- **One source for the published URL, scheme included.** The PDP document used to derive `http` vs
  `https` from the *global* TLS setting while the listener bound with the *plane's own*, so a data
  plane serving HTTPS could publish `http://` endpoints. Both documents now come from the same
  function, and the scheme from that endpoint's own TLS.

- **`permguard.pdp.v1` is named as what it is: Permguard's own interface.** It is not an
  implementation of, nor a compatibility claim for, any other authorization API, and the code and
  documentation no longer say otherwise. The shape will look familiar, because that is the obvious
  shape for the question; what changes is that the contract is Permguard's to specify and to
  evolve, without anyone having to ask whether somebody else's document still holds.

  - The discovery endpoint is now `GET /.well-known/permguard-pdp-v1-configuration`. The old path
    is **not mounted** and answers `404`.
  - The document is Permguard's own, identified by `interface: "permguard.pdp.v1"`, with
    `endpoints`, `capabilities` and `store_scope` — no longer borrowing another specification's
    field names.
  - Capabilities are namespaced `urn:permguard:pdp:v1:*`. Each names something implemented, tested,
    and answered identically over HTTP and gRPC.
  - A data plane's own `/.well-known/server-configuration` now carries `interfaces`, linking to the
    configuration above — so a client is given one URL and finds the rest.
  - Over gRPC, `GetMetadata` becomes `GetConfiguration` and returns the same document field for
    field.

- **`entities` is replaced by `partition_inputs`.** A request used to carry one entity graph for the
  whole profile, addressed to a *runtime*. That is unanswerable the moment a profile holds two
  partitions of the same runtime with different schemas: a graph legal for one is refused by the
  other, so the shape only ever worked while all but one partition ignored it. An input is now
  addressed to a **partition by name**, which is the only identity that separates them.

  ```json
  "partition_inputs": {
    "admin-cedar": { "type": "permguard.cedar.entities.v1", "data": [ … ] },
    "admin-rego":  { "type": "permguard.rego.data.v1",      "data": { … } }
  }
  ```

  `entities` is **refused**, never ignored — `field_removed`, on every binding, including gRPC,
  whose schema has no field to carry it and would otherwise have dropped it silently. The proto
  tags and names are reserved so nothing can be given them later.

- **A ledger declares what each partition accepts**, in `manifest.yml`:

  ```yaml
  admin-cedar:
    input: { type: permguard.cedar.entities.v1, required: true }
  ```

  The types are a fixed registry this build implements — `permguard.cedar.entities.v1` (a Cedar
  entity store) and `permguard.rego.data.v1` (a JSON document) — not names a caller invents. The
  `type` a request states is an assertion checked against the manifest's, never a selector: a
  caller cannot choose the parser for bytes it also supplies. `required: true` refuses a request
  that omits an input the partition's policies read, instead of deciding against an empty world.

- **Rego reads its input at `input.partition`**, not `data.entities`. `data` is the partition's own
  compiled world, identical for every request; grafting a caller's document into it made a global
  store that changed per evaluation — a shared surface nothing could validate.

- **The Helm chart's PodDisruptionBudget is one name and one number** (`budget: minAvailable`,
  `value: 1`) rather than two optional keys. A values file choosing one had to null the other out,
  and `helm template` honoured that null while `helm lint` did not: the same files rendered
  correctly and linted as a mistake nobody had made.

### Added

- **A decision has a deadline, and the engines are told about it.** The transport's request timeout
  ends the response; it does not end the work, which runs on a blocking thread that keeps going
  after the concurrency permit is released. Each decision now carries a budget — nine tenths of the
  transport's timeout — checked before a partition is evaluated and handed to Rego's interpreter as
  its execution limit. Rego's one-second budget bounded a single *rule*, so a partition with many
  modules could spend it many times over and still call itself bounded.

- **The evaluation queue is bounded.** Work is handed out through a fixed-depth channel; when it is
  full the submitting thread does the job itself. An unbounded queue was the wrong shape for a
  decision path — a request whose timeout has fired releases the permit that was limiting how many
  of these could be in flight, and with nothing bounding the queue that is how a plane under load
  accumulates work nobody is waiting for.

- **`extraVolumes` and `extraVolumeMounts` on every component of the chart.** The configuration
  names TLS certificates and authorities by path and the chart offered no way to put a file there:
  mutual TLS meant forking the chart or running a post-renderer.

- **`bench/decide.js`** measures the decision path — cold and warm, single and boxcarred — with
  thresholds on the warm path only. The rest of `bench/` measures the transport with nothing behind
  it, which was the whole suite until now.

- **A Rego partition can declare a schema.** `schema: true` plus one `.regoschema` file — JSON
  Schema, draft 2020-12, compiled once when the partition loads — and `input.partition` is checked
  against it before any rule runs. Rego is untyped by design and that is a virtue in a rule; it is
  not one in the data a rule reads, where a renamed field turns a guardrail into a rule that
  quietly never fires. Local only: a schema naming a remote `$ref` fails to compile rather than
  reaching for the network.

- **A profile's partitions are evaluated in parallel**, on a bounded process-wide pool, with the
  first job run by the calling thread — so a single-partition profile dispatches nothing and costs
  what it always did. Results come back in the manifest's order whatever order they finished in,
  and a partition that comes apart is a missing answer, which denies. The data plane runs the whole
  batch off the async runtime.

### Fixed

- **Tests no longer share fixed temporary directories.** Twelve suites named a directory after
  themselves, so two `cargo test` runs at once — or one after a run that left files behind —
  collided and failed for reasons unrelated to the code. Two full suites now run concurrently,
  green.

- **A plane id that names no plane is no longer read as the data plane.** Four places matched on a
  string and fell through to `data-plane`, so a typo produced a plausible document about the wrong
  process. `PlaneId` makes the wrong id unrepresentable.

- **The process registry is built from values, not string concatenation**, like the rest of the
  discovery documents.

- **A shared HTTP/gRPC port answers `404` for a path it does not serve.** The gRPC router's
  fallback took every unmatched path, so an HTTP client asking for a missing route was told
  `200 OK` with `grpc-status: 12` and an empty body. A gRPC caller still gets `UNIMPLEMENTED`; an
  HTTP caller now gets a `404` that says so. It matters most for discovery: a client probing for a
  document was being told "yes" by a port that serves nothing there.

- **gRPC and HTTP resolve a boxcarred batch the same way.** An evaluation stating
  `"partition_inputs": {}` replaces the request's defaults with nothing; one stating none inherits
  them. A proto3 `map` cannot tell an absent field from an empty one, so over gRPC `{}` was read as
  "unset" and *inherited* — the same request refused over HTTP and permitted over gRPC. The
  evaluation's field is a `PartitionInputs` message now, which has explicit presence; the old tag
  is reserved rather than reused, because a map and a message are different encodings.

- **The manifest refuses a key it does not know.** `deny_unknown_fields` on every YAML section, and
  the CBOR decoder — which documented itself as fail-closed and was not — rejects an unknown map
  key. `requred: true` was accepted and `required` stayed `false`: one transposed letter turning a
  partition whose data is mandatory into one where it is optional, silently, in the file whose
  whole job is to say what is mandatory. Forward compatibility is not lost, it is where the
  manifest already puts it: a ledger needing a newer reader says so in `runtimes.<key>.engine`, and
  the load gate refuses by name.

- **A profile must name at least one partition, and none of them twice**, and a manifest must
  declare at least one profile. A profile naming none can only ever deny, with nothing to cite; one
  naming a partition twice would ask it twice and cite it twice. Profile names now follow the same
  grammar as everything else the model names.

- **A boxcarred batch no longer copies its inputs once per evaluation.** With the default of 256
  evaluations, a one-megabyte entity store became hundreds of megabytes of identical copies before
  a policy had been consulted. Evaluations that inherit share one map; the resolved request is
  shared with the blocking evaluation rather than cloned into it.

- **gRPC no longer answers a request it did not fully receive.** The client hand-walked the JSON
  and dropped what it could not represent: a `context` that was not an object became no context,
  `evaluations: null` became no evaluations, an unknown `evaluations_semantic` became the default.
  It now reads the payload with the same `CheckRequest` the HTTP binding reads, then converts. The
  server refuses an enum value nobody defined instead of reading it as `execute_all`.

- **A schema file in a partition that declares none is refused**, not walked past. Skipping it was
  the worst of the three outcomes: the author sees the file, believes their inputs are validated,
  and nothing validates anything. The file extensions are asked of the language rather than
  hard-coded, so a second language with a schema is found.

## [0.1.2] - 2026-08-26

### Fixed

- Container registries no longer expose Cosign's internal `sha256-*.sig` artifacts as broken image
  versions. Image provenance remains available through GitHub Artifact Attestations, while release
  checksums remain signed with Cosign.
- Homebrew publishes the current CLI as `permguard/tap/cli` and its versioned aliases as
  `cli@<version>` and `cli@<major>`, without leaking the implementation language into the cask name.

## [0.1.1] - 2026-08-26

### Fixed

- Container images reach Docker Hub again, alongside GHCR. The release logged in to Docker Hub and
  then pushed nowhere near it: no `images:` entry ever named it. Versioned tags only — `latest` and
  `0.0` on those names still carry the Go implementation, and move when it does.
- The Helm chart's default images exist. `registry: ghcr.io` used to render
  `ghcr.io/permguard/control-plane`, a name that was never published; the registry value carries the
  namespace now, so `docker.io/permguard` and `ghcr.io/permguard/permguard` both resolve.

### Added

- `scripts/prepare-release.sh` and the `Prepare Release` workflow move the version, the lock, the
  chart and the changelog together, and create the tag from the result — so a tag can no longer
  reach the release pipeline describing a version the commit does not contain.

## [0.1.0] - 2026-08-25

The first release of the Rust workspace: the shared infrastructure crates, the reusable plane
modules, the deployable binaries, the decision endpoint and the decision log.

Nothing before this was released *from this workspace*. The `v0.0.x` line is the Go
implementation living in the same repository, and this is a different product versioned from
zero — so everything below is an addition, including the entries that read as fixes: they
record decisions taken while this release was being built, kept because the reasoning is worth
more than the tidiness of dropping them.

### Added

- **Contracts crate** (`permguard-core`): storage, secrets, signing keys, audit, services and the
  server host, as traits and the types they exchange, with a dependency allowlist enforced by
  `scripts/check-core-dependencies.sh`.
- **Default implementations** (`permguard-std`), one Cargo feature per area, with `provision` — the
  one that can mint a certificate authority — deliberately outside the default set.
- **One listener for every surface** (`permguard-transport`): TCP, TLS, mutual TLS, certificate
  revocation, material reload, and a shutdown that drains connections in flight.
- **Telemetry surface** (`permguard-telemetry`) on a port of its own: `/healthz`, `/readyz` and
  `/metrics`, with liveness and readiness reported separately.
- **Control plane and data plane**, each serving `GET /`, `/version` and `/health` over HTTP and
  `GetInfo`/`GetHealth` over gRPC, and an all-in-one runtime that hosts both.
- **Command line** (`permguard`) with `version`, `config` and `inspect`:
  - `inspect` probes every plane and reports `ready`, `degraded`, `unhealthy` or `unreachable`,
    each with a stable `reason` code, a latency and a UTC timestamp;
  - `config show`/`get`/`set`/`reset` over `~/.permguard/config.yml`, resolved through four layers —
    flag, environment, file, default — with `show` reporting which layer each value came from;
  - TLS and mutual TLS against a plane, including a client identity for a server that asks for one.
- **Deployment**: multi-architecture images for the CLI, the all-in-one runtime and both planes,
  published to Docker Hub and the GitHub Container Registry; a Helm chart; and a local lab with
  Prometheus, Grafana and Loki already wired to the planes.

- **Per-address connection bound** (`limits.connections_per_peer`, default 256): one client can no
  longer hold a surface's whole connection pool while every global number reads as healthy. Addresses
  in `limits.peer_exempt` — a load balancer, a health checker; single IPs or CIDR blocks — skip the
  per-address bound and still count toward the pool. Behind a load balancer the address seen is the
  balancer's, so there either exempt it or set the bound to `0` and let the ingress do the counting.
- **Connection lifetime** (`limits.connection_lifetime`, default unbounded): a connection past it is
  ended, which is what lets a deployment behind a balancer rotate connections.
- **Write-stall bound** (`limits.write_stall_timeout`, default 30s): a response that makes no progress
  for that long — a client that stopped reading its answer — ends the connection instead of stalling
  in the peer's TCP window forever.

- **Peer authorisation** (`tls.allow`, per endpoint): of everybody the client authority signed, an
  endpoint now answers only the peers its allow list names — `cn:`, `dn:` or `sha256:` entries, one
  per line. An authenticated peer off the list gets `403` and a log record naming it. An empty or
  absent list keeps the previous behaviour: the handshake is the whole decision. Configuring a list
  on an endpoint that demands no client certificate is refused at startup.
- **Build disclosure switch** (`public.disclose_build`, default `true`): set `false` and `/version`
  and gRPC `GetInfo` stop naming the version and commit, keeping plane and product so
  `permguard inspect` still identifies what answered.
- **Request-head byte bound** (`limits.header_bytes`, default 64k), covering HTTP/1 and HTTP/2.
- **CRL expiry gauge** `permguard_tls_crl_expiry_timestamp_seconds`, with a lab alert at seven days.
- A startup warning when secrets resolve from the environment outside development mode.
- The Helm chart refuses at template time the shape that enables the all-in-one beside a
  standalone plane: the all-in-one is both planes in one process, and mixing them is two
  deployments fighting over one identity.
- `operations.audit.refusals` (default `false`): when on, denied catalog operations land on the
  audit trail as `<operation>.refused` with the stable error code — for deployments whose
  compliance regime wants denied attempts on the record. Internal faults never reach the trail.
- `permguard completion bash|zsh|fish` prints shell completions, and every leaf command's `--help`
  now carries worked examples.
- The CLI's `-o json`/`-o yaml` now shape errors too: a refusal lands on stderr as the same
  `{class, code, message}` triple the server answers, exit statuses unchanged.
- **One error shape for every API** — `{class, code, message}` on HTTP and gRPC alike, the class
  deciding both status codes, gRPC carrying class and code as metadata. How much an `internal`
  error discloses follows `public.error_detail` (`full`/`minimal`; unset, `development_mode`
  decides, minimal by default) — the server's log always keeps the full detail.
- **Zones and ledgers** on the control plane: create, list, get, rename and delete, served
  identically over HTTP (`/v1/zones…`) and gRPC (`permguard.control.v1.ZoneCatalog`), stored on the
  volume as GUID-named directories with plain-JSON indexes — atomic replace for readers, per-scope
  locks for writers. Ids are UUIDv7; names are strict, URL-safe, and unique in their scope (zones
  across the deployment, ledgers within their zone). The CLI grows `permguard zones …` and
  `permguard ledgers --zone <name-or-id> …`, and every reference accepts the name or the id. All
  mutations land in the audit trail.
- **Authorization decisions** on the data plane: the `permguard.pdp.v1` profile — OpenID AuthZEN
  1.0 with Permguard's extensions — served identically over HTTP
  (`POST /access/v1/evaluation`, `/access/v1/evaluations`,
  `GET /.well-known/authzen-configuration`) and gRPC
  (`permguard.data.v1.PolicyDecisionPoint`). `zone` and `ledger` are **required fields of the
  payload**, by name or by identity: one endpoint answers for every ledger a plane holds, and a
  request naming neither is refused with `400` rather than answered against a default. Boxcarring
  and the three `options.evaluations_semantic` values are implemented; the standard's Search APIs
  are not served, and their absence from the metadata document is the declaration. Both built-in
  languages answer the same contract — Cedar through `cedar-policy`, Rego through `regorus` with a
  written convention (`allow` permits, `deny` overrides, absent means no). A deny is a `200` with
  `decision: false`; a ledger this plane does not mirror is `404`; one it may not serve is `503`.
  Every decision, permit and deny alike, lands in the audit trail with the id its response carries.
- **Schema enforcement at load**: a partition that declares `schema: true` has every policy
  type-checked against it, in strict mode, when it is compiled — a policy that does not satisfy the
  schema refuses the load instead of being served. With a schema, the request itself is validated
  too, so an action or a context attribute the ledger never declared is refused rather than silently
  ignored. (The Go implementation did neither.)
- **The decision cache** (`dataPlane.authz.cache.partitions`, default 64;
  `dataPlane.authz.cache.bytes`, default 256M; `dataPlane.authz.max_evaluations`, default 256): a
  ledger's policies are read off the volume once, compiled, and kept, so a decision is answered out
  of memory. The commit is part of the cache key, so a synchronization that advances a ledger needs
  no flush and a replaced commit is never served; the synchronization loop compiles a freshly
  mirrored ledger itself, so the first request after a sync is as fast as the thousandth. Least
  recently used entries are dropped when either bound is reached.
- **Unserveable ledgers are remembered** (`<mirror>/BLOCKED`): a ledger whose manifest this engine is
  outside the range of — or whose schema is no longer satisfied — is refused once and then skipped
  for the cost of one file read per round, until its commit changes. Nothing to configure, and a
  restart does not forget. `permguard_authz_blocked_ledgers` is the gauge to alert on.
- **Mirroring for the data plane** (`dataPlane.mirrors`): a plane follows a list of exact server URLs,
  each with anchored zone and ledger patterns — naming neither means everything that server lists —
  and keeps `<volume>/mirrors/<zone-id>/<ledger-id>` current on a cadence (`interval`, default 30s;
  `timeout` per ledger, default 2m; `parallelism`; `jitter`). Rounds never overlap: a tick that finds
  the previous one working is skipped. A server that does not answer never causes a deletion; a
  mirror the configuration or the server no longer names is removed, behind three guards. Per-server
  TLS material (`mirrors.servers[].tls`) with no "skip verification" anywhere. Every round is audited,
  including the quiet ones.
- **`permguard check`**: ask a data plane for a decision — a document (`-f file`, `-f -` for standard
  input) or flags (`--subject user:alice --action read --resource document:budget`), in
  `terminal`/`json`/`yaml`. Which store the question is about follows one rule shared by every
  command: flags win, then the workspace, then the document's own `zone`/`ledger`
  (`--ignore-workspace` sends it as written). **A deny exits 0** — it is an answer; only a request
  that could not be evaluated is a failure.
- **What a control plane holds, as metrics**: `permguard_store_bytes`,
  `permguard_zone_bytes{zone}`, `permguard_ledger_bytes{zone,ledger}`, `_ledger_objects` and
  `_ledger_counter`, measured by a walk of the store once a minute rather than accumulated — so they
  are true when they are read, and reconcile with `du`. Both lab dashboards were extended: the
  control plane gains disk per zone, ledgers by size and growth over time; the data plane gains
  decisions, latency, cache hit rate and occupancy, blocked ledgers and mirror freshness.
- **Reclaiming what nothing references.** A content-addressed store only ever adds: a push that
  never commits leaves objects nothing will reach, and so does a history that moved past a policy
  version. Now both sides reclaim them, under one rule — *keep what any ref reaches, plus anything
  younger than the grace period*.
  - The control plane sweeps on a cadence (`controlPlane.storage.gc`: `enabled` default true,
    `interval` default 6h, `grace` default 24h). Every sweep is audited, including the quiet ones,
    and reports `permguard_gc_objects_removed_total`, `_bytes_reclaimed_total`, `_objects_retained`
    and `_sweeps_total`.
  - `permguard objects prune` does the same for a workspace mirror, keeping what the tracked
    checkpoint or the staged snapshot reaches. `--dry-run` reports what would go without touching
    anything; `terminal`, `json` and `yaml` like every other command.
  - **The grace period is a safety property, not a knob**: during a push the uploaded objects are
    legitimately unreachable, so a sweep that ignored their age would delete the work of every push
    in flight. Values below 15 minutes are refused at startup. On the client the workspace lock
    plays the same role, so no grace period is needed there.
  - A closure with a hole stops the sweep for that ledger (and refuses the client's prune, pointing
    at `permguard verify`): a walk that cannot be completed cannot tell "unreachable" from
    "unreachable *from here*".
- **Load-test suite** (`bench/`, k6): closed-loop ceiling, open-model latency ladder, shed
  behaviour, gRPC and TLS/mTLS runs, with `task bench:*` targets, capacity and shed server
  profiles, a Prometheus remote-write receiver in the lab, and a **Permguard · Load test**
  dashboard overlaying what the client felt with what the server measured.

### Fixed while building this release

- **A partition towards one control plane no longer costs it its mirrors.** With several servers
  configured, reaping was driven by whatever the *answering* servers listed, so a server that could
  not be reached had its ledgers deleted from the plane — the exact opposite of the rule the loop
  claims. Reaping now considers only mirrors attributable to a server that answered this round (the
  `LEDGER` file beside each mirror records which server put it there); a mirror that names no server
  is left in place and reported. The previous test only covered a single configured server, which is
  the case where the bug cannot appear.
- **gRPC refusals now carry the same class and code HTTP does.** A refusal read `… (grpc/NotFound)`
  over gRPC and `… (not_found/no_ref)` over HTTP, so a caller telling "this ref does not exist yet"
  from "this failed" by reading the code was right on one transport and wrong on the other —
  `permguard checkout` of an empty ledger failed over `grpc://` and succeeded over `http://`. Both
  now produce `sentence (class/code)`, taken from the metadata the server already sends.
- **A changed schema or manifest is no longer reported as "no changes".** The workspace plan compared
  policies only, so an edited `*.cedarschema` — or an edited `manifest.yml` — produced an empty plan
  and never reached the server. The plan now also compares the manifest digest and each partition's
  subtree, and reports what it found (`~ cedar/schema`, `~ manifest`).

### Decided while building this release

- **`dataPlane.sync` is now `dataPlane.mirrors`**, and its environment variables moved from
  `PERMGUARD_SYNC_*` to `PERMGUARD_MIRRORS_*`. The block is named after what it keeps current — the
  mirrors on the volume — rather than after the act of keeping them, which matters now that a second
  thing on this plane will also synchronise (the decision log shipper). The keys inside are
  unchanged. Metric and log-event names are untouched: `permguard_sync_*` describes the loop's activity, and
  renaming them would break dashboards and alerts for no gain.

- **Revocation-list expiry is now enforced**: a CRL past its `nextUpdate` refuses every mutual-TLS
  handshake instead of being trusted forever. The gauge above predicts the moment.
- The TLS reload watcher compares file digests instead of modification times, so a rewrite inside
  one clock tick — or a copy that preserves times — is still noticed.
- Every GitHub Actions step is pinned to a commit SHA rather than a movable tag.
- `permguard_surface_connections_refused_total` now carries a `scope` label — `pool` or `peer` —
  saying which bound refused. Queries that sum by `surface` are unaffected.

[Unreleased]: https://github.com/permguard/permguard/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/permguard/permguard/releases/tag/v0.1.5
[0.1.2]: https://github.com/permguard/permguard/releases/tag/v0.1.2
[0.1.1]: https://github.com/permguard/permguard/releases/tag/v0.1.1
[0.1.0]: https://github.com/permguard/permguard/releases/tag/v0.1.0
