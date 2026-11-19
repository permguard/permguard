<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<!-- The running example's check, asked of the PDP from application code with each SDK: any failure is a deny. -->

::: code-group

```python [app.py]
from permguard import Action, Client, Entity, EvaluateRequest

request = EvaluateRequest(
    zone="quickstart",
    ledger="policies",
    subject=Entity(type="User", id="alice"),
    action=Action(name="read"),
    resource=Entity(type="Document", id="budget"),
)
try:
    with Client("grpc://localhost:7443") as pdp:
        permitted = pdp.evaluate(request).decision
except Exception:
    permitted = False  # no answer is a no: fail closed
```

```go [main.go]
import permguard "github.com/permguard/sdk-go"

permitted := false // no answer is a no: fail closed
if pdp, err := permguard.NewClient("grpc://localhost:7443"); err == nil {
	defer pdp.Close()
	answer, err := pdp.Evaluate(ctx, &permguard.EvaluateRequest{
		Zone:     "quickstart",
		Ledger:   "policies",
		Subject:  &permguard.Entity{Type: "User", ID: "alice"},
		Action:   &permguard.Action{Name: "read"},
		Resource: &permguard.Entity{Type: "Document", ID: "budget"},
	})
	permitted = err == nil && answer.Decision
}
```

```java [App.java]
import com.permguard.Client;
import com.permguard.Pdp;

var request = Pdp.EvaluateRequest.builder("quickstart", "policies")
        .subject(new Pdp.Entity("User", "alice"))
        .action(new Pdp.Action("read"))
        .resource(new Pdp.Entity("Document", "budget"))
        .build();
boolean permitted;
try (var pdp = new Client("grpc://localhost:7443")) {
    permitted = pdp.evaluate(request).decision();
} catch (RuntimeException e) {
    permitted = false; // no answer is a no: fail closed
}
```

```csharp [Program.cs]
using Permguard;
using PdpAction = Permguard.Action;

bool permitted;
try
{
    await using var pdp = new Client("grpc://localhost:7443");
    var answer = await pdp.EvaluateAsync(new EvaluateRequest("quickstart", "policies")
    {
        Subject = new Entity("User", "alice"),
        Action = new PdpAction("read"),
        Resource = new Entity("Document", "budget"),
    });
    permitted = answer.Decision;
}
catch (Exception)
{
    permitted = false; // no answer is a no: fail closed
}
```

```ts [app.ts]
import { Client } from "@permguard/permguard";

const pdp = new Client("grpc://localhost:7443");
let permitted: boolean;
try {
  const answer = await pdp.evaluate({
    zone: "quickstart",
    ledger: "policies",
    subject: { type: "User", id: "alice" },
    action: { name: "read" },
    resource: { type: "Document", id: "budget" },
  });
  permitted = answer.decision;
} catch {
  permitted = false; // no answer is a no: fail closed
} finally {
  pdp.close();
}
```

```rust [main.rs]
use permguard::{Action, Client, Entity, EvaluateRequest};

let mut request = EvaluateRequest::new("quickstart", "policies");
request.subject = Some(Entity::new("User", "alice"));
request.action = Some(Action::new("read"));
request.resource = Some(Entity::new("Document", "budget"));

// no answer is a no: fail closed
let permitted = match Client::new("grpc://localhost:7443") {
    Ok(pdp) => pdp.evaluate(&request).await.is_ok_and(|answer| answer.decision),
    Err(_) => false,
};
```

:::
