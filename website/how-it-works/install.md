---
pageClass: pg-page-concepts
title: Install Permguard
description: Install and verify the Permguard command-line interface on macOS, Linux or Windows.
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Install</div>
  <h1>One CLI. Your platform.</h1>
  <p>Install <code>permguard</code>, verify the release and start authoring policy.</p>
</div>

<div class="pgx-install-paths" role="img" aria-label="Permguard CLI can be installed with the release installer, Homebrew, Linux packages, PowerShell or Cargo.">
  <article class="pgx-install-paths__recommended"><small>FASTEST</small><strong>Release installer</strong><span>macOS · Linux · Windows</span></article>
  <article><small>PACKAGE MANAGER</small><strong>Homebrew</strong><span>macOS · Linux</span></article>
  <article><small>NATIVE PACKAGES</small><strong>deb · rpm · apk</strong><span>x86-64 · ARM64</span></article>
  <article><small>DEVELOPERS</small><strong>Cargo</strong><span>build from source</span></article>
</div>

## macOS and Linux

The installer detects the operating system and architecture, downloads the latest CLI archive, verifies its SHA-256 checksum and installs it in the directory you choose.

```sh
curl -fsSL https://raw.githubusercontent.com/permguard/permguard/main/install.sh \
  | sh -s -- -b "$HOME/.local/bin"

export PATH="$HOME/.local/bin:$PATH"
permguard version
```

When [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) is available, the installer also verifies the signed Sigstore bundle. Make that check mandatory with:

```sh
curl -fsSL https://raw.githubusercontent.com/permguard/permguard/main/install.sh \
  | PERMGUARD_VERIFY=signature sh -s -- -b "$HOME/.local/bin"
```

Pin a release by adding its tag after the options:

```sh
curl -fsSL https://raw.githubusercontent.com/permguard/permguard/main/install.sh \
  | sh -s -- -b "$HOME/.local/bin" v0.1.6
```

## Homebrew

Homebrew installs the macOS CLI release and keeps upgrades simple.

```sh
brew install permguard/tap/cli
permguard version
```

## Linux packages

Every release includes native packages for `x86_64` and `arm64`.

<div class="pgx-distro-grid" aria-label="Supported Linux package families">
  <article><small>DEB</small><strong>Debian family</strong><span>Ubuntu · Debian · Mint · Pop!_OS · elementary OS</span></article>
  <article><small>RPM</small><strong>RPM family</strong><span>Fedora · RHEL · Rocky · AlmaLinux · openSUSE</span></article>
  <article><small>APK</small><strong>Alpine Linux</strong><span>minimal and container-oriented systems</span></article>
</div>

Choose a version from [GitHub Releases](https://github.com/permguard/permguard/releases), then use the package for your distribution:

```sh
VERSION=v0.1.6
ARCH="$(case "$(uname -m)" in aarch64|arm64) echo arm64 ;; *) echo x86_64 ;; esac)"
BASE="https://github.com/permguard/permguard/releases/download/${VERSION}"
```

### Debian, Ubuntu and derivatives

```sh
curl -fLo permguard.deb "${BASE}/permguard_cli_Linux_${ARCH}.deb"
sudo apt install ./permguard.deb
```

### Fedora, RHEL, Rocky, AlmaLinux and openSUSE

```sh
curl -fLo permguard.rpm "${BASE}/permguard_cli_Linux_${ARCH}.rpm"
sudo rpm -Uvh ./permguard.rpm
```

### Alpine Linux

```sh
curl -fLo permguard.apk "${BASE}/permguard_cli_Linux_${ARCH}.apk"
sudo apk add --allow-untrusted ./permguard.apk
```

## Windows

Run the PowerShell installer from the directory where you want the local `bin` folder:

```powershell
iwr https://raw.githubusercontent.com/permguard/permguard/main/install.ps1 -UseBasicParsing | iex
./bin/permguard.exe version
```

It detects `x86_64` or `arm64`, downloads the matching ZIP and verifies its checksum. Move `permguard.exe` to a directory on `PATH` when you want it available in every shell.

## From source

Requires Rust 1.97 or newer.

```sh
git clone https://github.com/permguard/permguard.git
cd permguard
cargo install --path crates/permguard-cli --bin permguard --force
permguard version
```

## Verify a manual download

Release archives, packages, checksums, SBOMs and the Sigstore bundle live together on [GitHub Releases](https://github.com/permguard/permguard/releases). After downloading an artifact and these two files:

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/permguard/permguard/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

sha256sum --ignore-missing -c checksums.txt
```

## Shell completion

```sh
# Bash
permguard completion bash >> ~/.bashrc

# Zsh
permguard completion zsh > "${fpath[1]}/_permguard"

# Fish
permguard completion fish > ~/.config/fish/completions/permguard.fish
```

<div class="pgx-note"><strong>The CLI is not the server.</strong><span>It authors and moves policy, queries decisions and inspects deployments. The next pages show the release images and start the runtime.</span></div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="../how-it-works"><span>Previous</span><strong><b aria-hidden="true">←</b> How Permguard Works</strong></a>
  <a class="pgx-pager__next" href="./container-images"><span>Next</span><strong>Container Images <b aria-hidden="true">→</b></strong></a>
</nav>
