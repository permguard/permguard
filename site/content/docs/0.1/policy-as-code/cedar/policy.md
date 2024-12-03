---
title: "Cedar Policy"
slug: "Cedar Policy"
description: ""
summary: ""
date: 2023-08-21T22:44:39+01:00
lastmod: 2023-08-21T22:44:39+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "policy-grammar-6f7551118a914e7392a1acd29b1ef521"
weight: 4101
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
Policies can be created using the `Cedar Policy Language`.

Below is a sample directory structure that includes the schema file and sample policy files:

```plaintext
.
├── .permguard
├── schema.cedar
├── staff_policies.cedar
├── inventory_policies.cedar
```

Here is an example of cedar policy:

```cedar  {title="pharmacy.cedar"}
permit(
    principal in Role::"administer-platform-branches",
    action in Action::"create",
    resource in Resource::"pharmacy-branch"
);
```
