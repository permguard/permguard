---
title: "Cedar Language"
slug: "Cedar Language"
description: ""
summary: ""
date: 2023-08-21T22:44:39+01:00
lastmod: 2023-08-21T22:44:39+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "cedar-language-6f7551118a914e7392a1acd29b1ef521"
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
├── schema.cedar
├── staff_policies.cedar
├── inventory_policies.cedar
```

Here is an example of cedar policy:

```cedar  {title="pharmacy.cedar"}
permit(
    principal in Actor::"administer-platform-branches",
    action in Action::"create",
    resource in Resource::"pharmacy-branch"
);
```