<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<!-- The running example's rule as it is written today: an if hard-coded in an HTTP handler, in each SDK language. -->

::: code-group

```python [app.py]
@app.get("/budget")
def read_budget():
    user = current_user()
    if user.role != "finance" and user.id != "alice":
        abort(403)
    return serve_budget()
```

```go [main.go]
func readBudget(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user.Role != "finance" && user.ID != "alice" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	serveBudget(w)
}
```

```java [App.java]
@GetMapping("/budget")
Budget readBudget() {
    var user = currentUser();
    if (!user.role().equals("finance") && !user.id().equals("alice")) {
        throw new ResponseStatusException(HttpStatus.FORBIDDEN);
    }
    return serveBudget();
}
```

```csharp [Program.cs]
app.MapGet("/budget", (HttpContext http) =>
{
    var user = CurrentUser(http);
    if (user.Role != "finance" && user.Id != "alice")
    {
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }
    return ServeBudget();
});
```

```ts [app.ts]
app.get("/budget", (req, res) => {
  const user = currentUser(req);
  if (user.role !== "finance" && user.id !== "alice") {
    res.sendStatus(403);
    return;
  }
  serveBudget(res);
});
```

```rust [main.rs]
async fn read_budget(headers: HeaderMap) -> Result<Json<Budget>, StatusCode> {
    let user = current_user(&headers);
    if user.role != "finance" && user.id != "alice" {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(serve_budget())
}
```

:::
