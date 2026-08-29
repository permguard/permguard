<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# NOTICE

The **"Permguard"** name and its associated logo(s) are trademarks and intellectual property of **Nitro Agility S.r.l.**

All rights are reserved.
Unauthorized or misleading use of the "Permguard" name or logo — including imitation, false affiliation, or
representation suggesting endorsement by Nitro Agility — is strictly prohibited.

You may reference the **"Permguard" name and logo** in articles, comparisons, integrations, or documentation, **provided
such use is fair, accurate, and does not imply sponsorship or endorsement**.

For trademark or branding inquiries, please contact **<opensource@nitroagility.com>**.

## Third-party software

Permguard is distributed under Apache-2.0 and links third-party components under their own terms.
The complete dependency inventory and its licences are produced by `cargo deny check licenses` and
published with each release's SBOM; the entries below are the ones that carry an attribution or
notice obligation of their own.

### Dogwood

The experimental Dogwood policy runtime embeds the `amzn-dogwood-language` crate:

```text
Dogwood
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
```

Licensed under Apache-2.0. Source: <https://github.com/dogwood-policy/dogwood>, at the reviewed
revision recorded in `crates/permguard-languages/Cargo.toml`.

The example at `examples/dogwood-session-access/` is adapted from Dogwood's own
`dogwood-docs/examples/read_login_not_logout` bundle; Permguard changed the wire format, packaging
and deployment around it while preserving Dogwood's semantics. Neither Amazon nor the Dogwood
project endorses Permguard.

### smartstring (MPL-2.0)

Reached through `rhai`, the sandbox Dogwood evaluates information providers in:

```text
smartstring
Copyright (c) 2019 Bodil Stokke
```

Licensed under the Mozilla Public License 2.0. Permguard does **not** modify it. The MPL is
file-level copyleft: the obligation attaches to the licensed files themselves and not to the
program that links them, which the licence states explicitly (MPL-2.0 §3.3). The source is
available at <https://crates.io/crates/smartstring> and
<https://github.com/bodil/smartstring>, and the licence text travels with the crate.

© 2025 **Nitro Agility S.r.l.** All Rights Reserved.
