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
weight: 4103
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---
**Permguard** integrates `Cedar` as policy language. Here you can find the <a href="https://www.cedarpolicy.com/" target="_blank" rel="noopener noreferrer">official documentation</a>.

Policies are written using the `Cedar Policy Language`.

{{< callout context="danger" icon="alert-octagon" >}}
Permguard mandates the use of the @id annotation in Cedar policies. This is required to uniquely identify each policy.
{{< /callout >}}

Below is an example directory structure with a schema file and sample policy files:

```plaintext
.
├── .permguard
├── schema.json
├── staff_policies.cedar
```

Here is an example of cedar policy.

```cedar  {title="pharmacy.cedar"}
@id("platform-creator")
permit(
  principal == Permguard::IAM::RoleActor::"platform-creator",
  action == MagicFarmacia::Platform::Action::"create",
  resource is MagicFarmacia::Platform::Subscription
)
when {
  context.isSubscriptionActive == true
    && action.isEnabled == true && resource.isEnabled == true
}
unless {
  principal.isSuperUser == false
};
```
