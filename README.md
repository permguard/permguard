# PermGuard

[![Documentation](https://img.shields.io/website?label=Docs&url=https%3A%2F%2Fwww.permguard.com%2F)](https://www.permguard.com/)
[![PermGuardCI](https://github.com/permguard/permguard/actions/workflows/permguard-ci.yml/badge.svg)](https://github.com/permguard/permguard/actions/workflows/permguard-ci.yml)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=bugs)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=coverage)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)
[![Go Report Card](https://goreportcard.com/badge/github.com/permguard/permguard)](https://goreportcard.com/report/github.com/permguard/permguard)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=permguard_permguard&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=permguard_permguard)


`PermGuard` an Open Source Multi-Account and Multi-Tenant Authorization Provider that implements the authorization layer, enabling the segregation of the application's authorization logic from the core application code.

As an `PermGuard administrator` you can create multiple accounts and create multiple schemas within each account.

All you have to do is describe your schema's `resources` within your account and create your own access control policies. Resources are organized into schema's domains.

`PermGuard` allows to specify who or what can access resources by the means of fine-grained permissions:

- `Who`: *Identities (Users and Roles) authenticated in the application*
- `Can Access`: *Permissions granted by attaching policies*
- `Resources`: *Resources targeted by permissions*

To enforce the access control process, the application implements the Policy Enforcement Point using the available SDKs

![alt text](assets/vscode/vscode-screenshot.png)
