<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Verify Released Container Images

Permguard publishes the same release images to GitHub Container Registry (GHCR) and Docker Hub.
The release workflow records their digests in a cryptographically signed GitHub Artifact
Attestation. Verification proves that the selected registry object is the object produced by the
Permguard release workflow for the expected Git tag.

## Published images

| Component | GHCR | Docker Hub |
| --- | --- | --- |
| CLI | `ghcr.io/permguard/permguard/cli` | `docker.io/permguard/cli` |
| All-in-one | `ghcr.io/permguard/permguard/all-in-one` | `docker.io/permguard/all-in-one` |
| Control plane | `ghcr.io/permguard/permguard/control-plane` | `docker.io/permguard/control-plane` |
| Data plane | `ghcr.io/permguard/permguard/data-plane` | `docker.io/permguard/data-plane` |

## Prerequisites

Install the GitHub CLI and Docker, then authenticate both the GitHub CLI and the registry being
checked. `gh attestation verify` requires access to GitHub's attestation API and to the OCI manifest
in the registry.

```sh
gh auth login
docker login docker.io
```

For GHCR, authenticate with a GitHub token that can read packages:

```sh
printf '%s' "${GHCR_TOKEN}" | docker login ghcr.io --username USERNAME --password-stdin
```

Do not put tokens directly in command history.

## Verify a Docker Hub image

Set the release version without the leading `v`, then verify the image against the repository,
signing workflow and exact release tag:

```sh
VERSION=0.1.2

gh attestation verify \
  "oci://docker.io/permguard/all-in-one:${VERSION}" \
  --repo permguard/permguard \
  --signer-workflow permguard/permguard/.github/workflows/release-pipeline.yml \
  --source-ref "refs/tags/v${VERSION}"
```

Change `all-in-one` to `cli`, `control-plane` or `data-plane` to verify another component.

## Verify a GHCR image

The policy is identical; only the image location changes:

```sh
VERSION=0.1.2

gh attestation verify \
  "oci://ghcr.io/permguard/permguard/all-in-one:${VERSION}" \
  --repo permguard/permguard \
  --signer-workflow permguard/permguard/.github/workflows/release-pipeline.yml \
  --source-ref "refs/tags/v${VERSION}"
```

## Verify the immutable digest

A version tag is convenient but movable. For deployment admission or an audit record, resolve it
once and verify the immutable digest instead:

```sh
IMAGE=docker.io/permguard/all-in-one:0.1.2

docker pull "${IMAGE}"
DIGEST_REF="$(docker image inspect "${IMAGE}" --format '{{index .RepoDigests 0}}')"

gh attestation verify \
  "oci://${DIGEST_REF}" \
  --repo permguard/permguard \
  --signer-workflow permguard/permguard/.github/workflows/release-pipeline.yml \
  --source-ref refs/tags/v0.1.2
```

Deploy the resulting `name@sha256:...` reference when reproducibility matters.

## Automation

The verifier exits with status zero only when every enforced identity and digest check succeeds, so
the same command can gate a deployment:

```sh
gh attestation verify \
  "oci://docker.io/permguard/all-in-one:${VERSION}" \
  --repo permguard/permguard \
  --signer-workflow permguard/permguard/.github/workflows/release-pipeline.yml \
  --source-ref "refs/tags/v${VERSION}" \
  >/dev/null
```

In unattended environments, provide GitHub authentication through `GH_TOKEN` and authenticate the
OCI registry before running the check.

## Troubleshooting

### No attestations found

Confirm that the release pipeline completed its `Attest container images` step and that `--repo`
names `permguard/permguard`. A tag pushed before the release completed may exist before its
attestation does.

### The OCI image cannot be loaded

Authenticate the registry again. Authentication for `gh` and authentication for Docker are
separate: `gh auth login` does not perform `docker login`.

### A `sha256-....sig` tag appears

Releases `0.1.0` and `0.1.1` used Cosign's legacy registry storage, which represented a signature as
a `sha256-....sig` tag. It is signature metadata, not a runnable image, and `docker pull` must not be
used on it. Current releases use GitHub Artifact Attestations and do not create new `.sig` tags.
