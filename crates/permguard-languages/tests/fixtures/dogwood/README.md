<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Dogwood fixtures

`read-login-not-logout.*` are the artifacts of Dogwood's own
`dogwood-docs/examples/read_login_not_logout` example, copied verbatim from the reviewed upstream
revision (see `NOTICE.md` for the attribution, and `crates/permguard-languages/Cargo.toml` for the
revision itself).

They are here rather than paraphrased so the test that uses them proves something worth proving:
that Permguard's Dogwood partition, loaded from a ledger commit and driven through Permguard's own
event contract, reproduces the verdicts upstream's `expected.out` records for the same policy, the
same schema and the same sequence of events. A schema written here to suit the test would prove
that the test passes.

Upstream's `expected.out`, for the trace in `read_login_not_logout_trace`:

```text
@0    (time point 0): DENY
@100  (time point 1): ALLOW  [rules: 0]
@4000 (time point 2): DENY
@4100 (time point 3): DENY
```
