---
title: "Naming Conventions"
slug: "Naming Conventions"
description: ""
summary: ""
date: 2023-08-21T22:44:39+01:00
lastmod: 2023-08-21T22:44:39+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "naming-conventions-1a456dcd418c4468819b5f22c56d52d6"
weight: 4002
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Permguard strictly enforces naming conventions across all schemas and policies to ensure consistency.

A key requirement is that everything must be in lowercase. To enhance the user experience during provisioning, all files will be automatically converted to lowercase before being provisioned to the Permguard server.

Additionally, all names within the schema are validated using a predefined [validators](/docs/0.1/internals/validators/common-validators) pattern.

There are only two exceptions:

- **UUR (Universally Unique Resource)**: This is used to identify a resource within a policy or enforcement point.
- **RA (Resource Action)**: This is used to identify a resource-bound action within a policy or enforcement point.

## UUR (Universally Unique Resource)

The `UUR` is a unique identifier used to specify resources within policies and enforcement points. The format includes five placeholders as follows:

- `{partition}`: The partition represents a deployment instance. It should be left blank for now, but it is reserved for future use.
- `{account}`: The account associated with the resource. This field can be left blank, in which case it will default to the current account.
- `{tenant}`: The tenant within which the resource resides.
- `{domain}`: The domain or functional area of the resource.
- `{resource}`: The specific resource being identified.
- `{resource-filter}`: An optional filter to further narrow down the resource (e.g., specific IDs or categories).

This structure allows precise identification and management of resources in a multi-tenant, multi-domain environment.

Below is an example of a UUR that identifies an inventory item with the ID `b51cbd37503f4a4eaec9d2f33419d523` in the domain `pharmacy-branch`, which belongs to the tenant `matera-branch` under the account `581616507495`:

```plaintext
uur::581616507495:matera-branch:pharmacy-branch:inventory/b51cbd37503f4a4eaec9d2f33419d523
```

Each placeholder, except the `{account}` placeholder, can either be an exact value or use the wildcard pattern `*` to match multiple values.

```plaintext
uur::581616507495:matera-branch:pharmacy-*:inventory/*
```

Additionally, for the `{tenant}` placeholder, you can use the dynamic value $tenant, which associates the tenant at runtime based on the execution context:

```plaintext
uur::$account:$tenant:pharmacy-*:inventory/*
```

It is also possible to leave the `{account}` and `{tenant}` placeholders blank, in which case they will default to the current account (`$account`) and tenant (`$tenant`), respectively:

```plaintext
uur::::pharmacy-*:inventory/*
```

{{< callout context="caution" icon="alert-triangle" >}}
Wildcard and dynamic value patterns are not permitted when referencing a resource in an enforcement point; only exact values are allowed.
{{< /callout >}}

It is important to note that for resources related to identities, the exact account identifier must be used, and permguard must be specified as the tenant:

```plaintext
uur::581616507495::iam:identity/google/pharmacist
```

## AR (Action Resource)

The AR is an action resource structured identifier used to specify actions that can be performed on resources within policies and enforcement points. The format includes two placeholders as follows:

- `{resource}`: The specific resource on which the action is performed.
- `{action}`: The specific action to be performed on the resource (e.g., read, write, delete).

This structure enables precise specification and control of actions on resources, allowing for fine-grained policy enforcement in complex environments.

Below is an example of an AR that identifies a read action on an inventory in the context of the pharmacy-branch domain:

```plaintext
ra:inventory:view
```

Each placeholder can either be an exact value or use the wildcard pattern `*` to match multiple values:

```plaintext
ra:inv*:*
```
