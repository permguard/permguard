# Plan: Move Internal-Only Packages from `pkg/` to `internal/`

> **Status:** Draft
> **Date:** 2026-03-05
> **Scope:** Reduce public API surface by moving packages only used within the main module to `internal/`

---

## Context

After the architecture restructuring (Phase 3), several packages remain in `pkg/` that are **not imported by any sub-module** (`ztauthstar/`, `notp-protocol/`, `plugin/storage/sqlite/`, `ztauthstar-cedar/`). These packages are implementation details exposed as public API.

Additionally, `pkg/cli/*.go` files have already been moved to `internal/cli/clilib/` but the old copies were not deleted.

---

## Immediate Cleanup: Delete Stale `pkg/cli/*.go` Files

The following files are **stale copies** — all imports already point to `internal/cli/clilib/`:

| File | Status |
|------|--------|
| `pkg/cli/cli_printer.go` | **DELETE** — moved to `internal/cli/clilib/cli_printer.go` |
| `pkg/cli/cli_context.go` | **DELETE** — moved to `internal/cli/clilib/cli_context.go` |
| `pkg/cli/cli_infos.go` | **DELETE** — moved to `internal/cli/clilib/cli_infos.go` |
| `pkg/cli/cli_initializer.go` | **DELETE** — moved to `internal/cli/clilib/cli_initializer.go` |
| `pkg/cli/docs.go` | **DELETE** — moved to `internal/cli/clilib/docs.go` |
| `pkg/cli/options/` | **KEEP** — imported by `plugin/storage/sqlite` |

---

## Packages to Move: Analysis

### 1. `pkg/agents/servers/` → `internal/agents/servers/pkg/`

**Confidence:** 90%

**Current importers (main module only):**
- `internal/agents/servers/server.go`

**Contains:** Server factory, config, server context — all internal bootstrapping code.

**Risk:** Low — only used by the server bootstrap layer within the main module.

---

### 2. `pkg/agents/services/` → `internal/agents/services/pkg/`

**Confidence:** 85%

**Current importers (main module only):**
- `internal/agents/services/pap/controllers/pap_controller.go`
- `internal/agents/services/pdp/controllers/pdp_controller.go`
- `internal/agents/services/zap/controllers/zap_controller.go`
- `internal/agents/services/pap/pap_svc.go` and similar
- `internal/agents/services/zap/endpoints/api/v1/zap_grpc_server.go` and similar

**Contains:** `ServiceContext`, `EndpointContext`, service configuration types.

**Risk:** Medium — widely used within `internal/agents/services/` but NOT by external modules. However, this is the "framework" for building services, so if external plugins ever need to implement services, they'd need this.

**Recommendation:** Move, but double-check the plugin extensibility design first.

---

### 3. `pkg/authz/engines/` + `pkg/authz/languages/` → `internal/authz/`

**Confidence:** 90%

**Current importers (main module only):**
- `internal/agents/services/pdp/pdp_svc_config.go` (engines)
- `plugin/languages/cedar/` (languages) — **NOTE:** this is in the main module, not a sub-module

**Contains:** Abstract interfaces for auth engines and language abstractions.

**Risk:** Low — internal abstractions for the plugin system. The `ztauthstar-cedar/` module does NOT import these directly.

---

### 4. `pkg/core/files/` → `internal/core/files/`

**Confidence:** 95%

**Current importers (main module only):**
- `internal/agents/services/pdp/controllers/pdp_controller.go`

**Contains:** File utility functions (read, write, append).

**Risk:** Very low — pure utility code.

---

## Migration Steps (Per Package)

For each package move:

1. Copy files from `pkg/X/` to `internal/X/` (or chosen target path)
2. `find . -name "*.go" ! -name "*.pb.go" | xargs sed -i '' 's|old/import/path|new/import/path|g'`
3. Run `go build ./...` across all workspace modules
4. Run `go test ./...` to verify
5. Delete the old `pkg/X/` directory
6. Run `go build ./...` again to ensure no stale references

## Execution Order

1. Delete stale `pkg/cli/*.go` (zero risk)
2. Move `pkg/core/files/` → `internal/core/files/` (lowest risk)
3. Move `pkg/authz/` → `internal/authz/` (low risk)
4. Move `pkg/agents/servers/` → `internal/agents/pkgservers/` (low risk)
5. Move `pkg/agents/services/` → `internal/agents/pkgservices/` (medium risk, most files affected)

## What MUST Stay in `pkg/`

| Package | Reason |
|---------|--------|
| `pkg/agents/runtime/` | Imported by `plugin/storage/sqlite` |
| `pkg/agents/storage/` | Imported by `plugin/storage/sqlite` |
| `pkg/cli/options/` | Imported by `plugin/storage/sqlite` |
| `pkg/core/validators/` | Imported by `plugin/storage/sqlite` |
| `pkg/extensions/*` | Imported by `ztauthstar/` and `notp-protocol/` |
| `pkg/provisioners/storage/` | Public provisioner interface for plugins |
| `pkg/transport/clients/` | Public client interface for external consumers |
| `pkg/transport/models/*` | Shared data models (`pap/` and `zap/` by plugin, `pdp/` for external PDP clients) |
