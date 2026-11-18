---
pageClass: pg-page-concepts
title: Install Permguard
description: Install the Permguard CLI and Permguard Admin on macOS, Linux or Windows, and verify what you downloaded.
outline: [2, 3]
---

<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<div class="pgx-doc-hero">
  <div class="pgx-kicker">Install</div>
  <h1>Two tools. Your platform.</h1>
  <p>The Permguard CLI for terminals and pipelines. Permguard Admin for the desktop, with the CLI inside.</p>
</div>

<div class="pgx-cards pgx-cards--2">
  <a class="pgx-card" href="#permguard-cli"><span>Terminal · pipeline</span><h3>Permguard CLI</h3><p>Author, validate, test offline and publish policy with <code>permguard</code>.</p><b aria-hidden="true">↓</b></a>
  <a class="pgx-card pgx-card--accent" href="#permguard-admin"><span>Desktop</span><h3>Permguard Admin</h3><p>Ledgers, decision logs and the CLI of every ledger, in one application.</p><b aria-hidden="true">↓</b></a>
</div>

## Permguard CLI

<div class="pgx-install-paths" role="img" aria-label="Permguard CLI can be installed with the release installer, Homebrew, Linux packages, PowerShell or Cargo.">
  <article class="pgx-install-paths__recommended"><small>FASTEST</small><strong>Release installer</strong><span>macOS · Linux · Windows</span></article>
  <article><small>PACKAGE MANAGER</small><strong>Homebrew</strong><span>macOS · Linux</span></article>
  <article><small>NATIVE PACKAGES</small><strong>deb · rpm · apk</strong><span>x86-64 · ARM64</span></article>
  <article><small>DEVELOPERS</small><strong>Cargo</strong><span>build from source</span></article>
</div>

### macOS and Linux

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

### Homebrew

Homebrew installs the macOS CLI release and keeps upgrades simple.

```sh
brew trust permguard/tap      # once: Homebrew 7 loads casks only from trusted taps
brew install permguard/tap/permguard-cli
permguard version
```

### Linux packages

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

#### Debian, Ubuntu and derivatives

```sh
curl -fLo permguard.deb "${BASE}/permguard_cli_Linux_${ARCH}.deb"
sudo apt install ./permguard.deb
```

#### Fedora, RHEL, Rocky, AlmaLinux and openSUSE

```sh
curl -fLo permguard.rpm "${BASE}/permguard_cli_Linux_${ARCH}.rpm"
sudo rpm -Uvh ./permguard.rpm
```

#### Alpine Linux

```sh
curl -fLo permguard.apk "${BASE}/permguard_cli_Linux_${ARCH}.apk"
sudo apk add --allow-untrusted ./permguard.apk
```

### Windows

Run the PowerShell installer from the directory where you want the local `bin` folder:

```powershell
iwr https://raw.githubusercontent.com/permguard/permguard/main/install.ps1 -UseBasicParsing | iex
./bin/permguard.exe version
```

It detects `x86_64` or `arm64`, downloads the matching ZIP and verifies its checksum. Move `permguard.exe` to a directory on `PATH` when you want it available in every shell.

### From source

Requires Rust 1.97 or newer.

```sh
git clone https://github.com/permguard/permguard.git
cd permguard
cargo install --path crates/permguard-cli --bin permguard --force
permguard version
```

### Verify a manual download

Release archives, packages, checksums, SBOMs and the Sigstore bundle live together on [GitHub Releases](https://github.com/permguard/permguard/releases). After downloading an artifact and these two files:

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/permguard/permguard/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

sha256sum --ignore-missing -c checksums.txt
```

### Shell completion

```sh
# Bash
permguard completion bash >> ~/.bashrc

# Zsh
permguard completion zsh > "${fpath[1]}/_permguard"

# Fish
permguard completion fish > ~/.config/fish/completions/permguard.fish
```

## Permguard Admin

The desktop application for operating Permguard: it clones the ledgers of a Control Plane into a workspace, shows their history and decision logs, and runs the CLI on every ledger.
It needs nothing else installed: the Permguard CLI is inside it, at the version it was built with.

<div class="pgx-distro-grid" aria-label="Permguard Admin can be installed with Homebrew, with one command, or by hand from the release installers.">
  <article><small>MACOS</small><strong>Homebrew</strong><span>the same tap as the CLI</span></article>
  <article><small>ONE COMMAND</small><strong>Install script</strong><span>macOS · Linux · Windows</span></article>
  <article><small>BY HAND</small><strong>Installers</strong><span>dmg · exe · msi · deb · rpm · AppImage</span></article>
</div>

### Homebrew

On macOS, from the same tap as the Permguard CLI:

```sh
brew trust permguard/tap      # once: Homebrew 7 loads casks only from trusted taps
brew install permguard/tap/permguard-admin
```

Install a given version with `brew install permguard/tap/permguard-admin@0.1.0`; update with `brew upgrade permguard-admin`.

### One command

The install scripts download the latest release, check it against `checksums.txt` and install it.

```sh
# macOS and Linux
curl -fsSL https://raw.githubusercontent.com/permguard/permguard-admin-releases/main/install.sh | sh
```

```powershell
# Windows, in PowerShell
irm https://raw.githubusercontent.com/permguard/permguard-admin-releases/main/install.ps1 | iex
```

| System  | What the script installs                                                                                                                       |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| macOS   | the application, into `/Applications`, or `~/Applications` when that is not writable                                                           |
| Linux   | the `.deb` or the `.rpm`, whichever your system uses, otherwise the `.AppImage` in `~/.local/bin`; `-t deb`, `-t rpm` or `-t appimage` chooses |
| Windows | the setup, for your user, without administrator rights; `-Installer msi` installs the `.msi` for the whole machine                             |

Pin a release by passing its tag:

```sh
curl -fsSL https://raw.githubusercontent.com/permguard/permguard-admin-releases/main/install.sh | sh -s -- v0.1.0
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/permguard/permguard-admin-releases/main/install.ps1))) -Version v0.1.0
```

### By hand

Download the installer for your system from [Permguard Admin releases](https://github.com/permguard/permguard-admin-releases/releases/latest).

| System  | Installer                                              |
| ------- | ------------------------------------------------------ |
| macOS   | `_darwin_universal.dmg`, Apple silicon and Intel       |
| Windows | `_windows_amd64_setup.exe` or `_windows_amd64.msi`     |
| Linux   | `.deb`, `.rpm` or `.AppImage`, for `amd64` and `arm64` |

On macOS, open the `.dmg` and drag Permguard Admin into Applications.
On Windows, run the setup, or the `.msi` for managed installations.
On Linux, install the `.deb` with `sudo apt install ./permguard-admin_*.deb` or the `.rpm` with `sudo dnf install ./permguard-admin_*.rpm`; the `.AppImage` runs without installing once made executable with `chmod +x`.

Each release carries `checksums.txt`, to check that the file you downloaded is the one published:

```sh
shasum -a 256 -c checksums.txt --ignore-missing
```

<div class="pgx-note"><strong>Neither tool is the server.</strong><span>The CLI and Permguard Admin author and move policy, query decisions and inspect deployments. The next page shows the server images.</span></div>

<nav class="pgx-pager" aria-label="Documentation pages">
  <a class="pgx-pager__previous" href="../how-it-works"><span>Previous</span><strong><b aria-hidden="true">←</b> How Permguard Works</strong></a>
  <a class="pgx-pager__next" href="./container-images"><span>Next</span><strong>Containers <b aria-hidden="true">→</b></strong></a>
</nav>
