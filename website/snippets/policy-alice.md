<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<!-- The running example's rule, in each policy language: the same rule, written in the language you choose.
     Both versions pass `permguard test` offline: permit for alice, deny for bob, each naming `alice-can-read`. -->

::: code-group

```cedar [documents.cedar]
@alias("alice-can-read")
permit (
    principal == User::"alice",
    action == Action::"read",
    resource == Document::"budget"
);
```

```rego [documents.rego]
# METADATA
# custom:
#   alias: alice-can-read
package documents.access

import rego.v1

default allow := false

allow if {
	input.subject.type == "User"
	input.subject.id == "alice"
	input.action.name == "read"
	input.resource.type == "Document"
	input.resource.id == "budget"
}
```

:::
