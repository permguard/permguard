# Permguard

[![Documentation](https://img.shields.io/website?label=Docs&url=https%3A%2F%2Fwww.permguard.com%2F)](https://www.permguard.com/)
[![PermguardCI](https://github.com/permguard/permguard/actions/workflows/permguard-ci.yml/badge.svg)](https://github.com/permguard/permguard/actions/workflows/permguard-ci.yml)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=bugs)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=coverage)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)
[![Go Report Card](https://goreportcard.com/badge/github.com/permguard/permguard)](https://goreportcard.com/report/github.com/permguard/permguard)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)

[![Watch the video on YouTube](https://raw.githubusercontent.com/permguard/permguard-assets/refs/heads/main/video/permguard-thumbnail-preview.png)](https://www.youtube.com/watch?v=x2hRB2b59yc)

[Watch the video on YouTube](https://www.youtube.com/watch?v=x2hRB2b59yc)

Learn:

- [Permguard Docs](https://www.permguard.com/)
- [ZTAuth*: Zero Trust AuthN/AuthZ Models and Trusted Delegations](https://medium.com/ztauth)

**Permguard** is an Open Source Zero-Trust Auth* Provider for cloud-native, edge, and multi-tenant apps, decoupled from application code and leveraging `Policy-as-Code` for centralized, scalable permission management.

As a `PermGuard administrator`, you can create multiple accounts and manage multiple repositories within each account.

Simply define your schema's `resources` within your repository and create customized access control policies. Resources are organized into schema namespaces.

**Permguard** allows to specify who or what can access resources by the means of fine-grained permissions:

- `Who`: *Identities (Users and Actors) authenticated in the application*
- `Can Access`: *Permissions granted by attaching policies*
- `Resources`: *Resources targeted by permissions*

To enforce the access control process, the application implements the Policy Enforcement Point using the available SDKs

<p align="center">
  <img src="https://github.com/permguard/permguard/blob/main/assets/permguard.png?raw=true" class="center"/>
</p>

Created by [Nitro Agility](https://www.nitroagility.com/).
