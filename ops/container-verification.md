<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Verify Released Container Images

Permguard publishes the same release images to GitHub Container Registry (GHCR) and Docker Hub.
The release workflow records their digests in a cryptographically signed GitHub Artifact
Attestation. Verification proves that the selected registry object is the object produced by the
Permguard release workflow for the expected Git tag.

The signing workflow is `release-build.yml`, the reusable workflow that builds and attests every release after `0.1.6`.
Releases up to and including `0.1.6` were attested by `release-pipeline.yml`: verify those with `--signer-workflow permguard/permguard/.github/workflows/release-pipeline.yml`.

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
  --signer-workflow permguard/permguard/.github/workflows/release-build.yml \
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
  --signer-workflow permguard/permguard/.github/workflows/release-build.yml \
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
  --signer-workflow permguard/permguard/.github/workflows/release-build.yml \
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
  --signer-workflow permguard/permguard/.github/workflows/release-build.yml \
  --source-ref "refs/tags/v${VERSION}" \
  >/dev/null
```

In unattended environments, provide GitHub authentication through `GH_TOKEN` and authenticate the
OCI registry before running the check.

## Verify at deploy with the Helm chart

The chart runs the same check before any Permguard container starts.
With `imageVerification.enabled`, every Permguard Pod — the Control Plane, the all-in-one, each data plane group, the drain Job and the drain controller — starts with a `verify-image` init container that runs `gh attestation verify` on the digest the Pod runs.
An image that fails it never starts, and its Pod never becomes Ready.

| Value                                  | What it is                                                                                  |
| -------------------------------------- | ------------------------------------------------------------------------------------------- |
| `imageVerification.enabled`            | on in `values-production.yaml`; a `regulated` workload refuses to render without it         |
| `imageVerification.verifier.image`     | an image whose entrypoint is `gh`, by digest; `docker/verifier/Dockerfile` builds one       |
| `imageVerification.tokenSecret`        | the Secret and key holding the GitHub token the attestation API is read with                |
| `imageVerification.repository`         | the source repository the provenance must name, `permguard/permguard`                       |
| `imageVerification.signerWorkflow`     | the builder, `permguard/permguard/.github/workflows/release-build.yml`                      |
| `imageVerification.sourceRef`          | the tag the image was built from; empty means `refs/tags/v<appVersion>`                     |
| `<component>.digest`                   | each enabled component's image digest, `sha256:<hex>`, required while verification is on    |

The components are `controlPlane`, `dataPlane`, `allInOne` and `dataPlane.drainController`.
Take each digest from the release's `provenance-images.txt`, so the digest the Pod runs is the one the release attested.
Build and push the verifier, then name it by its digest:

```sh
docker build -f docker/verifier/Dockerfile -t registry.example/permguard-verifier:2.98.0 docker/verifier
docker push registry.example/permguard-verifier:2.98.0
kubectl create secret generic permguard-image-verification --from-file=token=gh-token.txt
```

Release `0.1.5` was attested by `release-pipeline.yml`: deploy it with `imageVerification.signerWorkflow: permguard/permguard/.github/workflows/release-pipeline.yml` and `imageVerification.sourceRef: refs/tags/v0.1.5`.
The images of `0.1.6` carry no attestation the check finds (the attestation API answers `404` for their digests), so `0.1.6` cannot run with verification on.
No release has been built by `release-build.yml` yet, so the chart's defaults verify no published image today.

The check runs at every Pod start — a restart after a node reboot, a scale-up, a drain Job — and needs api.github.com, Sigstore's trust root and the image registry, read anonymously, reachable from the Pods.
Behind a default-deny egress policy, or during a GitHub outage, new Pods do not start: the check fails closed.

## Troubleshooting

### No attestations found

Confirm that the release builder completed its `Attest the container images` step and that `--repo`
names `permguard/permguard`. A tag pushed before the release completed may exist before its
attestation does.

### The OCI image cannot be loaded

Authenticate the registry again. Authentication for `gh` and authentication for Docker are
separate: `gh auth login` does not perform `docker login`.

### A `sha256-....sig` tag appears

Releases `0.1.0` and `0.1.1` used Cosign's legacy registry storage, which represented a signature as
a `sha256-....sig` tag. It is signature metadata, not a runnable image, and `docker pull` must not be
used on it. Current releases use GitHub Artifact Attestations and do not create new `.sig` tags.
