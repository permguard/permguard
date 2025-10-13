---
title: "Get the CLI"
slug: "Get the CLI"
description: ""
summary: ""
date: 2023-08-15T14:47:57+01:00
lastmod: 2023-08-15T14:47:57+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "install-cli-7eeb8755487e42f08067cf5569233a62"
weight: 1002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Permguard offers multiple installation options. Review the methods below to choose the one that best fits your environment.

## Official Package Managers

Official package managers maintained by the Permguard team and updated with every release.

### Homebrew <img alt="macOS" src="https://img.shields.io/badge/MacOS-000000?logo=apple&logoColor=F0F0F0" height="20"> <img alt="Linux" src="https://img.shields.io/badge/Linux-FCC624?logo=linux&logoColor=black" height="20"> {#homebrew}

Using [Homebrew](https://brew.sh/), users can install Permguard on macOS and Linux with the following command:

```shell [bash]
brew update
brew install permguard/tap/cli
```

## Get The Binary

### MacOS & Linux

The latest release binary can be downloaded and installed to the system path.

```bash
curl -fsSL https://raw.githubusercontent.com/permguard/permguard/refs/heads/main/install.sh | sh -s
```

The binary should then be moved into the system path:

```shell [bash]
sudo mv ./bin/permguard /usr/local/bin/
chmod +x /usr/local/bin/permguard
```

The installation can be verified with:

```shell [bash]
permguard --version
```

### Windows

The PowerShell install script can be used:

```powershell [powershell]
Invoke-WebRequest -Uri https://raw.githubusercontent.com/permguard/permguard/refs/heads/main/install.ps1 -UseBasicParsing | Invoke-Expression
```

If the binary was downloaded manually, it should be moved to a folder included in the PATH:

```powershell [powershell]
Move-Item .\bin\permguard.exe "C:\Program Files\permguard\permguard.exe"
setx PATH "$($env:PATH);C:\Program Files\permguard"
```

The installation can be verified with:

```shell [bash]
permguard --version
```

## Official Package Formats

Official package formats maintained by the Permguard team and updated with every release.

### deb <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-E95420?logo=ubuntu&logoColor=white" height="20"> <img alt="Debian" src="https://img.shields.io/badge/Debian-A81D33?logo=debian&logoColor=white" height="20"> <img alt="Linux Mint" src="https://img.shields.io/badge/Linux_Mint-87CF3E?logo=linuxmint&logoColor=fff" height="20"> <img alt="Pop!_OS" src="https://img.shields.io/badge/Pop!_OS-48B9C7?logo=popos&logoColor=fff" height="20"> <img alt="Elementary OS" src="https://img.shields.io/badge/Elementary_OS-64BAFF?logo=elementary&logoColor=fff" height="20">  {#deb}

The following example demonstrates how to install `permguard` using the `deb` package format on Debian-based systems:

```bash
# Download and install the package
# Make sure to adjust the VERSION variable to the desired release version
VERSION="v0.0.11"; ARCH=$( [ "$(uname -m)" = "aarch64" ] && echo "arm64" || echo "x86_64" ); curl -fsSL -o permguard.deb "https://github.com/permguard/permguard/releases/download/${VERSION}/permguard_cli_Linux_${ARCH}.deb"
sudo dpkg -i permguard.deb
```

The installation may be verified using the following command:

```shell [bash]
permguard --version
```

To uninstall the package, use:

```bash
sudo dpkg -r permguard
```

### rpm <img alt="Fedora" src="https://img.shields.io/badge/Fedora-51A2DA?logo=fedora&logoColor=fff" height="20"> <img alt="CentOS" src="https://img.shields.io/badge/CentOS-002260?logo=centos&logoColor=F0F0F0" height="20"> <img alt="Red Hat Enterprise Linux" src="https://img.shields.io/badge/Red_Hat-EE0000?logo=redhat&logoColor=white" height="20"> <img alt="Rocky Linux" src="https://img.shields.io/badge/Rocky_Linux-10B981?logo=rockylinux&logoColor=fff" height="20"> <img alt="AlmaLinux" src="https://img.shields.io/badge/AlmaLinux-0F4C81?logo=almalinux&logoColor=fff" height="20"> <img alt="openSUSE" src="https://img.shields.io/badge/openSUSE-73BA25?logo=opensuse&logoColor=fff" height="20"> {#rpm}

The following example demonstrates how to install `permguard` using the `deb` package format on Debian-based systems:

```bash
# Download and install the package
# Make sure to adjust the VERSION variable to the desired release version
VERSION="v0.0.11"; ARCH=$( [ "$(uname -m)" = "aarch64" ] && echo "arm64" || echo "x86_64" ); curl -fsSL -o permguard.rpm "https://github.com/permguard/permguard/releases/download/${VERSION}/permguard_cli_Linux_${ARCH}.rpm"
sudo rpm -i permguard.rpm
```

The installation may be verified using the following command:

```shell [bash]
permguard --version
```

To uninstall the package, use:

```bash
sudo rpm -e permguard
```

### apk <img alt="Alpine Linux" src="https://img.shields.io/badge/Alpine_Linux-0D597F?logo=alpinelinux&logoColor=white" height="20">
 {#apk}

The following example demonstrates how to install `permguard` using the `deb` package format on Debian-based systems:

```bash
# Download and install the package
# Make sure to adjust the VERSION variable to the desired release version
VERSION="v0.0.11"; ARCH=$( [ "$(uname -m)" = "aarch64" ] && echo "arm64" || echo "x86_64" ); curl -fsSL -o permguard.apk "https://github.com/permguard/permguard/releases/download/${VERSION}/permguard_cli_Linux_${ARCH}.apk"
sudo apk add --allow-untrusted permguard.apk
```

The installation may be verified using the following command:

```shell [bash]
permguard --version
```

To uninstall the package, use:

```bash
sudo apk del permguard
```

## Setup completions

Command-line completions can be generated for Bash, Zsh, Fish, or PowerShell to enhance the CLI experience.

```shell [bash]
# ~/.bashrc
permguard completion bash >> ~/.bash_completion
```

```shell [zsh]
# ~/.zshrc
permguard completion zsh >> ~/.zshrc
```

```shell [fish]
# ~/.config/fish/config.fish
permguard completion fish >> ~/.config/fish/config.fish
```

```powershell [powershell]
# $PROFILE\Microsoft.PowerShell_profile.ps1
permguard completion powershell | Out-String | Invoke-Expression
```

## Verify the binaries

To ensure the integrity and authenticity of a Permguard release, the desired version should be specified before running the verification process.
The following example demonstrates the recommended verification procedure for users..

{{< callout context="note" icon="info-circle" >}}
The official release binaries are available on the project’s [GitHub Releases](https://github.com/permguard/permguard/releases) page.
It is recommended to download binaries exclusively from this source to ensure their authenticity and integrity.
{{< /callout >}}

```bash
# Set the version you want to verify
VERSION=v0.0.11

# Download the checksums file for the selected version
wget https://github.com/permguard/permguard/releases/download/${VERSION}/checksums.txt

# Verify the checksums file using cosign
cosign verify-blob \
  --certificate-identity "https://github.com/permguard/permguard/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --cert "https://github.com/permguard/permguard/releases/download/${VERSION}/checksums.txt.pem" \
  --signature "https://github.com/permguard/permguard/releases/download/${VERSION}/checksums.txt.sig" \
  ./checksums.txt

# Download the SBOM and the release artifact
wget https://github.com/permguard/permguard/releases/download/${VERSION}/permguard_cli_Linux_x86_64.tar.gz.sbom.json
wget https://github.com/permguard/permguard/releases/download/${VERSION}/permguard_cli_Linux_x86_64.tar.gz

# Verify the integrity of the downloaded files
sha256sum --ignore-missing -c checksums.txt
```
