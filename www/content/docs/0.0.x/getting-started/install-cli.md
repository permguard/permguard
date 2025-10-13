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

[TO BE COMPLETED]

## Get The Binary

Download the latest release binary and install the the os path.

```bash
curl -fsSL https://raw.githubusercontent.com/permguard/permguard/refs/heads/main/install.sh | sh -s
```

## Official Package Formats

Official package formats maintained by the Permguard team and updated with every release.

### deb <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-E95420?logo=ubuntu&logoColor=white" height="20"> <img alt="Debian" src="https://img.shields.io/badge/Debian-A81D33?logo=debian&logoColor=white" height="20"> <img alt="Linux Mint" src="https://img.shields.io/badge/Linux_Mint-87CF3E?logo=linuxmint&logoColor=fff" height="20"> <img alt="Pop!_OS" src="https://img.shields.io/badge/Pop!_OS-48B9C7?logo=popos&logoColor=fff" height="20"> <img alt="Elementary OS" src="https://img.shields.io/badge/Elementary_OS-64BAFF?logo=elementary&logoColor=fff" height="20">  {#deb}

[TO BE COMPLETED]

### rpm <img alt="Fedora" src="https://img.shields.io/badge/Fedora-51A2DA?logo=fedora&logoColor=fff" height="20"> <img alt="CentOS" src="https://img.shields.io/badge/CentOS-002260?logo=centos&logoColor=F0F0F0" height="20"> <img alt="Red Hat Enterprise Linux" src="https://img.shields.io/badge/Red_Hat-EE0000?logo=redhat&logoColor=white" height="20"> <img alt="Rocky Linux" src="https://img.shields.io/badge/Rocky_Linux-10B981?logo=rockylinux&logoColor=fff" height="20"> <img alt="AlmaLinux" src="https://img.shields.io/badge/AlmaLinux-0F4C81?logo=almalinux&logoColor=fff" height="20"> <img alt="openSUSE" src="https://img.shields.io/badge/openSUSE-73BA25?logo=opensuse&logoColor=fff" height="20"> {#rpm}

[TO BE COMPLETED]

### apk <img alt="Alpine Linux" src="https://img.shields.io/badge/Alpine_Linux-0D597F?logo=alpinelinux&logoColor=white" height="20">
 {#apk}

[TO BE COMPLETED]

## Setup completions

Generate command-line completions for Bash, Zsh, Fish, or PowerShell to enhance your CLI experience.

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

To ensure the integrity and authenticity of a Permguard release, the desired version must be specified before running the verification process.
The following example demonstrates the recommended verification procedure.

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
