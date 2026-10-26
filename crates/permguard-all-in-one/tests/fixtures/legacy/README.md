<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The baseline volume

`baseline-8390f612/volume` is the whole working directory an all-in-one of commit `8390f612` left behind, captured once by `scripts/capture-baseline-volume.sh`.
`baseline-8390f612/capture.json` records what that server answered and when the capture was taken; `tests/baseline_volume.rs` recovers the volume with today's binaries.

The private keys under `volume/operations/keys/` and the secrets under `volume/operations/secrets/` are throwaway development material.
The baseline's `autogenerate: true` minted them seconds before the capture, nothing outside this fixture trusts them, and they sign and protect nothing but the fixture itself.
A secret scanner that reports them reports this fixture, not a credential.

The volume is kept byte for byte as the baseline wrote it, apart from every `LOCK` emptied and empty directories removed: change nothing inside it by hand.
Capture it again only with the script, and the test's expectations with it.
