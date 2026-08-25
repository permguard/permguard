<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Releasing

Pushing a tag matching `v[0-9]+.[0-9]+.[0-9]+*` runs the release pipeline, which refuses to build
unless the tag matches the workspace version in `Cargo.toml`. One tag produces every artifact:

- a **GitHub release** carrying CLI archives, all-in-one archives, plane archives, `deb`/`rpm`/`apk`
  packages, checksums and SBOMs, for Linux, macOS and Windows on x86-64 and arm64;
- **container images** for the CLI, the all-in-one runtime and the two planes, pushed to Docker Hub
  **and** to the GitHub Container Registry — the same digests in both, so neither registry is the
  one that has to be up.

See [Containers](docker.md) for the image names.

## Verifying a release

The `checksums.txt` of every release is signed with **cosign, keyless**: the signature
(`checksums.txt.sig`) and its Fulcio certificate (`checksums.txt.pem`) sit beside it on the
release. The trust roots are the public Sigstore infrastructure and GitHub's OIDC issuer — a valid
signature proves the checksums file was produced by a workflow of this repository, not merely
fetched from the same place as the archive:

```sh
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/permguard/permguard-rust/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

`install.sh` and `install.ps1` run this check themselves when `cosign` is installed, and
`PERMGUARD_VERIFY=signature` makes its absence fatal instead of a note. The SHA-256 check alone
protects against transfer corruption, not against a compromised release channel — which is why the
signature exists.

Container images are signed by cosign at the published digest. The release also emits `digests.txt`
for the image references, and the pipeline attaches GitHub provenance attestations for both
`checksums.txt` and `digests.txt`; verify images by digest rather than by a mutable tag.

## Configuration files

Each plane keeps its own configuration files under its crate directory:

- `config.local.yml`
- `config.local-tls.yml`
- `config.local-mtls.yml`
- `config.docker.yml`
- `config.docker-tls.yml`
- `config.lab.yml`
- `config.template.yml`

The current config surface is deliberately minimal: development mode, autogeneration, public
HTTP/gRPC protocol switches, addresses, and TLS/mTLS per plane protocol, telemetry address,
operations keys, secrets, and audit. Standalone plane configs declare one plane section; all-in-one
declares `runtime`, `controlPlane`, and `dataPlane`.
