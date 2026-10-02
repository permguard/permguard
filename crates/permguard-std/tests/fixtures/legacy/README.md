<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Legacy volume fixtures

Each directory under `v1/` is a volume fragment written by the current code and read back by `tests/legacy_fixtures.rs`.
They are the v1 compatibility baseline: every later migration of the catalog, the key ring or the audit trail must read them.

The private keys under `v1/keys/` and `v1/audit/keys/` are throwaway test keys.
The test minted them at capture time, nothing outside this fixture trusts them, and they sign nothing but the fixture itself.

Git does not keep file modes, so a checkout holds these keys world-readable while the key manager writes them with mode `0600`.
A later change that refuses world-readable keys has to account for this fixture.
