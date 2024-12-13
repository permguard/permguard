---
title: "Language"
slug: "Language"
description: ""
summary: ""
date: 2023-08-21T22:44:39+01:00
lastmod: 2023-08-21T22:44:39+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "language-6f7551118a914e7392a1acd29b1ef521"
weight: 4101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
**PermGuard** integrates `Cedar` as policy language. Here you can find the <a href="https://www.cedarpolicy.com/" target="_blank" rel="noopener noreferrer">official documentation</a>.

Policies are written using the `Cedar Policy Language`.

Below is an example directory structure with a schema file and sample policy files:

```plaintext
.
├── .permguard
├── schema.json
├── staff_policies.cedar
```

Here is an example of cedar policy:

```cedar  {title="pharmacy.cedar"}
@policy_id("assign-role-branch")
permit(
    principal in Permguard::Actor::"administer-branches-staff",
    action in Action::"assignRole",
    resource in MagicFarmacia::Branch::Staff::"role"
)
when {
  principal.active == true &&
  context.id > 0
}
unless {
  principal has isTerminated && principal.isTerminated
};
```
