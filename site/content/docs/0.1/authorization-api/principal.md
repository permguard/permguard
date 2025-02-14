---
title: "Principal"
slug: "Principal"
description: ""
summary: ""
date: 2024-12-26T22:53:00+01:00
lastmod: 2024-12-26T22:53:00+01:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "principal-c47c495e-e89f-4ae1-a279-b21d97e2d427"
weight: 5202
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `Principal` is the entity performing the action being authenticated, with the authority to act on behalf of the `Subject`.
While the `Principal` and `Subject` are usually the same, there are scenarios where the `Principal` is not the same of the `Subject`.

```json
{
  "authorization_context": {
    "principal": {
      "type": "user",
      "id": "amy.smith@acmecorp.com",
      "source": "keycloak",
      "identity_token": "eyJhbGciOiJI...",
      "access_token": "eyJhbGciOiJI..."
    }
  }
}
```
