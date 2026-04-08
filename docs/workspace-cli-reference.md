# Workspace CLI - Reference Guide

Reference for the Permguard CLI workspace: internal logic, command flows, file system layout, and file formats.

---

## Part 1: How It Works

### Ignore Rules

When scanning for source files, the workspace applies these ignore rules:

| Pattern | What it ignores |
|---------|-----------------|
| `.permguard/` | The workspace internal directory |
| `.permguardignore` | The ignore file itself (like `.gitignore` syntax) |
| `.git/` | Git directory |
| `.gitignore` | Git ignore file |
| Schema file names | When scanning for code files (e.g. `permguard.schema`) |
| Code file extensions | When scanning for schema files (e.g. `*.cedar`) |
| Other partition paths | When scanning partition `/`, ignores sub-partition paths |

The `.permguardignore` file works like `.gitignore`: patterns listed in it are excluded from scanning.

---

### Manifest Detection

The workspace supports three manifest file names: `manifest.json`, `manifest.yaml`, and `manifest.yml`.
Only **one** may exist at a time; if multiple are found, an error is raised.

The detected format (`"json"` or `"yaml"`, never `"yml"`) is stored in the manifest blob's `MetaKeyFormat` metadata.
On pull, the manifest is written to disk in the format declared by the blob metadata, and any existing manifest file in a different format is deleted.

| Local file | Server format | Pull result |
|------------|---------------|-------------|
| `manifest.json` | `yaml` | Delete `.json`, write `.yaml` |
| `manifest.yml` | `json` | Delete `.yml`, write `.json` |
| `manifest.yml` | `yaml` | Delete `.yml`, write `.yaml` |

YAML manifest files must contain valid YAML syntax (not JSON inside a `.yaml`/`.yml` extension).

---

### Scanning

The scanning phase finds all relevant source files in the workspace directory.

```
For each partition in manifest:
  1. Get language abstraction for partition
     -> policy extensions (e.g. [".cedar"])
     -> schema names (e.g. ["permguard.schema"])

  2. Scan for policy files (Kind="code")
     Walk from partition root (e.g. "./" for "/")
     Include: files matching extensions
     Ignore: .permguard, .git, .permguardignore, .gitignore, schema files, other partitions
     Result: CodeFile[] with { Kind:"code", Partition, Path }

  3. Scan for schema files (Kind="schema")
     Walk from partition root
     Include: files matching schema names exactly
     Ignore: .permguard, .git, code files, other partitions
     Result: CodeFile[] with { Kind:"schema", Partition, Path }
     Note: schema files are always scanned regardless of the schema flag,
           so existing files are preserved even when schema is disabled.

  4. Deduplicate ignored files (remove if also included)
```

Output: `selectedFiles[]` (to blobify) + `ignoredFiles[]` (for verbose display)

---

### Blobification (the core)

`blobifyLocal` is the heart of the workspace. It takes scanned files and produces the full local state.

```
Input: selectedFiles []CodeFile (only Kind, Partition, Path filled)

Step 1: CREATE BLOBS
  For each file:
    Read content + mode from disk

    If Kind="code" (policy file):
      absLang.CreatePolicyBlobObjects(lang, partition, path, data)
        Language parser splits file into individual policies
        Each policy -> SectionObject:
          obj:       *Object (CBOR blob with OID)
          partition: partition path
          otype:     "blob"
          oname:     policy name (e.g. "allow-read")
          metadata:  {code-id, code-type-id, language-id, ...}
          numOfSect: section index
          err:       nil or parsing error
        Returns: MultiSectionsObject { path, sections[], numOfSects }

    If Kind="schema" (schema file):
      Validate: max 1 schema per partition
      absLang.CreateSchemaBlobObjects(lang, partition, path, data)
        Same flow, single section

    For each SectionObject:
      buildCodeFileFromSection()
        Enriches CodeFile with: OID, OType, OName, CodeID, CodeTypeID,
          LanguageID, LanguageVersionID, LanguageTypeID, Mode, Section, HasErrors
        If no error:
          cospMgr.SaveCodeSourceObject(oid, content)
            -> Write blob to .permguard/code/@workspace/objs/XX/...rest_of_oid

Step 2: WRITE CODEMAP
  cospMgr.SaveCodeSourceCodeMap(blobifiedCodeFiles)
    -> Write CSV: .permguard/code/@workspace/codemap
    (maps source files to blob objects, includes errors)

Step 3: ABORT IF ERRORS
  If any CodeFile has HasErrors=true -> return error
  (codemap is still written so errors can be displayed)

Step 4: WRITE CODESTATE
  ConvertCodeFilesToCodeObjectStates(codeFiles)
    CodeFile[] -> CodeObjectState[] (drops file-level fields, keeps object-level)
  cospMgr.SaveCodeSourceCodeState(codeObjectStates)
    -> Write CSV: .permguard/code/@workspace/codestate
  Note: manifest is NOT included in the CSV codestate.
        It is added dynamically during plan calculation.

Step 5: BUILD TREE
  objects.NewTree(partition)
  For each CodeObjectState:
    objects.NewTreeEntry(OType, OID, OName, DataType, metadata)
    tree.AddEntry(entry)
      Dedup: reject if OName or CodeID+CodeTypeID already exists
  objects.CreateTreeObject(tree)
    -> CBOR serialize -> envelope -> compute OID
  cospMgr.SaveCodeSourceObject(treeID, treeContent)
    -> Write tree to .permguard/code/@workspace/objs/XX/...

Step 6: CREATE MANIFEST BLOB
  DetectManifestFile(workspaceDir)
    -> Find manifest.json, manifest.yaml, or manifest.yml (error if >1 or 0)
  Read manifest file content from disk
  Create blob with header: DataType=DataTypeManifest, MetaKeyFormat=detected format
  cospMgr.SaveCodeSourceObject(manifestOID, manifestContent)

Step 7: WRITE CONFIG
  cospMgr.SaveCodeSourceConfig(treeID, manifestID)
    -> Write TOML: .permguard/code/@workspace/config

Step 8: VALIDATE SCHEMA (per partition)
  For each partition:
    If schema is enabled (manifest partition.schema=true):
      If no schema file found -> ERROR with message explaining
        schema is required and how to fix (add file or set schema=false)
    If schema is disabled (schema=false):
      If schema file exists -> included normally (blobified)
      If schema file missing -> silently skipped (no error)

Output: treeID (string), manifestID (string), blobifiedCodeFiles []CodeFile
```

---

### Plan Calculation

After blobification, the plan compares local state against remote HEAD.

```
Input: local codestate + remote commit (from last pull)

1. Read local state:
   cospMgr.ReadCodeSourceCodeState()
     -> CodeObjectState[] from .permguard/code/@workspace/codestate
   Add local manifest from config:
     cospMgr.ReadCodeSourceConfig() -> manifestID
     Append CodeObjectState{OName:"manifest", OID:manifestID, DataType:TreeDataTypeManifest}

2. Read remote state:
   CurrentHeadCommit(ref) -> get commit (for manifest OID)
   CurrentHeadTree(ref)
     -> Read commit from .permguard/objs/ -> get tree OID -> read tree
   cospMgr.BuildCodeSourceCodeStateForTree(remoteTree)
     -> Walk tree entries -> CodeObjectState[]
   Add remote manifest from commit:
     Append CodeObjectState{OName:"manifest", OID:commit.Manifest(), DataType:TreeDataTypeManifest}

3. Compare by OName:
   CalculateCodeObjectsState(local, remote)
     Build localMap[OName] and remoteMap[OName]
     For each local:
       same OID in remote  -> "unchanged"
       diff OID in remote  -> "modify"
       not in remote       -> "create"
     For each remote not in local:
       -> "delete"
   Note: manifest appears in the plan as a regular entry.
         Format changes (json->yaml) change the blob OID -> shown as "modify".

4. Save plan:
   cospMgr.SaveRemoteCodePlan(ref, plan)
     -> Write CSV: .permguard/code/{ref}/plan
```

---

### Push (apply)

After plan, apply builds a commit and pushes to the server.

```
1. Build tree from plan:
   NewTree(partition)
   For each non-delete, non-manifest item: NewTreeEntry(...)
     Manifest entries (DataType=TreeDataTypeManifest) are SKIPPED
     (manifest is referenced from the commit, not the tree)
   CreateTreeObject(tree) -> treeObj
   SaveCodeSourceObject(treeObj) -> persist to code source

2. Build commit:
   Read manifestID from code source config
   NewCommit(treeCID, manifestCID, parentCID, timestamps)
   CreateCommitObject(commit) -> commitObj

3. Push to server (3 phases):
   Phase 1 - ADVERTISE:
     Client -> Server: ZoneID, LedgerID, commitOID, prevRemoteOID
     Server -> Client: TxID, conflicts?, up-to-date?

   Phase 2 - TRANSFER HISTORY (ancestor commits):
     Walk commit chain from local to remote
     For each ancestor: send commit + manifest + tree + blobs

   Phase 3 - TRANSFER CURRENT:
     Send current commit + manifest + tree + blobs (from @workspace/objs/)
     Server verifies graph integrity (commit -> manifest -> tree -> blobs)
     Server -> Client: Committed (bool)

4. Cleanup:
   Delete .permguard/code/@workspace/
   Delete .permguard/code/{ref}/plan
```

---

### Pull

Downloads objects from server and regenerates source files.

```
1. Pull objects (3 phases):
   Phase 1 - STATE:
     Client -> Server: localCommitOID
     Server -> Client: serverCommitOID, numCommits

   Phase 2 - NEGOTIATE:
     Client -> Server: localOID, remoteOID
     Server -> Client: CommitIDs[] to download

   Phase 3 - OBJECTS:
     For each commitID:
       Server -> Client: Objects[] { OID, OType, Content }
         (includes commit, manifest blob, tree, and all tree entry blobs)
       Verify OID integrity (recompute from content)
       Save to .permguard/objs/XX/...
       Verify commit graph (commit -> manifest -> tree -> blobs all exist)

2. Write manifest file:
   Read manifest blob from .permguard/objs/
   Read format from blob header (MetaKeyFormat: "json" or "yaml")
   Delete any existing manifest files in other formats
   Write manifest content to disk with correct extension

3. Regenerate source files:
   Read remote tree entries
   For each entry:
     Skip manifest-type blobs (DataType=DataTypeManifest)
     Read blob content from .permguard/objs/
     Classify by code-type-id:
       schema -> collect per partition
       policy -> convert to human-readable language
         absLang.ConvertBytesToHumanLanguage(...)
   For each partition:
     Write policy file: absLang.CreatePolicyContentBytes(blocks)
     Write schema file: absLang.CreateSchemaContentBytes(blocks)

4. Update HEAD refs
```

---

## Part 2: CLI Commands

### `permguard refresh`

```
1. cleanupLocalArea()         -> delete .permguard/code/@workspace/
2. buildManifestLanguageProvider() -> detect manifest file (json/yaml/yml), map partitions
3. scanSourceCodeFiles()      -> find policy + schema files
4. blobifyLocal()             -> THE CORE (see Part 1)
```

### `permguard validate`

```
1. execInternalRefresh()      -> full refresh (errors are propagated, not ignored)
2. retrieveCodeMap()          -> read codemap, split valid/invalid
3. If invalid files exist     -> report errors (shown in both verbose and normal mode)
```

### `permguard plan`

```
1. currentHeadContext()       -> read HEAD ref, remote info
2. execInternalValidate()     -> refresh + validation (gate)
3. CurrentHeadCommit(ref)     -> read remote commit (for manifest OID)
4. CurrentHeadTree(ref)       -> read remote tree from .permguard/objs/
5. Add manifest to both local and remote code states
6. CalculateCodeObjectsState() -> compare local vs remote (including manifest)
7. SaveRemoteCodePlan()       -> write plan CSV
```

### `permguard apply`

```
1. execInternalPlan()         -> recalculate plan
2. ReadRemoteCodePlan()       -> read plan
3. buildPlanTree()            -> plan -> tree object (manifest entries skipped)
4. SaveCodeSourceObject()     -> persist plan tree to code source
5. ReadCodeSourceConfig()     -> get manifest ID
6. buildPlanCommit()          -> tree + manifest -> commit object
7. execPush()                 -> push to server (3 phases)
8. execInternalPull()         -> pull back from server
```

### `permguard pull`

```
1. execInternalRefresh()      -> refresh local
2. execRemotePull()           -> pull from server (3 phases)
3. Write manifest file        -> format-aware (json/yaml), deletes old format
4. Regenerate source files    -> from remote tree (skips manifest blobs)
```

### `permguard objects cat <OID> --inspect`

Output varies by object type:
- **Commit**: shows TREE, MANIFEST, PARENT, AUTHOR, timestamps, MESSAGE
- **Tree**: shows TYPE, PARTITION, OID, ONAME, CODE-ID, CODE-TYPE, LANGUAGE, LANG-VERSION, LANG-TYPE
  - Entries with zero metadata IDs show empty strings (not "0")
- **Blob (manifest)**: shows only DATA-TYPE column
- **Blob (code)**: shows DATA-TYPE, CODE-ID, CODE-TYPE, LANGUAGE, LANG-VERSION, LANG-TYPE

JSON output (`--output json`):
- **Manifest blobs**: `data_type_id`, `data_type_name`, `metadata`, `data`
- **Code blobs**: adds `code_id`, `code_type_id`, `code_type`, `language_id`, `language`, `language_version_id`, `language_version`, `language_type_id`, `language_type`

### `permguard objects cat <OID> --human`

- **Code blobs**: converts AST to human-readable language (tries all partitions if blob lacks partition metadata)
- **Manifest blobs**: converts to YAML (if content is JSON) or shows as-is (if already YAML)

---

## Part 3: File System Layout

```
project-root/
  manifest.json | manifest.yaml | manifest.yml <- Workspace manifest (only one allowed)
  .permguardignore                       <- Ignore patterns (like .gitignore)
  *.cedar                                <- Policy source files
  permguard.schema                       <- Schema files (optional if schema=false)

  .permguard/
    permguard.lock                       <- Workspace lock (flock)

    config/
      config                             <- TOML: registered ledgers

    refs/
      remote                             <- TOML: server definitions
      heads                              <- TOML: HEAD pointer
      {zone}/{ledger}/{ref}/
        config                           <- TOML: ref config (upstream, commit)

    logs/
      pulls                              <- CSV: pull history
      pushes                             <- CSV: push history

    code/
      @workspace/                        <- LOCAL STATE (rebuilt on every refresh)
        config                           <- TOML: current tree ID + manifest ID (see File F1)
        codemap                          <- CSV: file -> blob mapping (see File F2)
        codestate                        <- CSV: code object states (see File F3)
        objs/
          XX/                            <- Sharded by last 2 chars of OID
            ...rest_of_oid               <- Raw CBOR content (blob or tree)

      {ref}/                             <- PER-REF PLAN STATE
        plan                             <- CSV: calculated plan (see File F4)

    objs/                                <- REMOTE OBJECT STORE (from pull)
      XX/
        ...rest_of_oid                   <- Commits, trees, blobs from server
```

---

## Part 4: File Formats

### File F1: COSP Config

**Path:** `.permguard/code/@workspace/config`
**Format:** TOML
**Written by:** `SaveCodeSourceConfig(treeID, manifestID)` after blobification
**Read by:** internal tree/manifest reference lookup during plan and apply

```toml
[codestate]
treeid = "bafyrei..."
manifestid = "bafyrei..."
```

| Field | Type | Description |
|-------|------|-------------|
| `treeid` | string | OID of the tree object built during the last refresh |
| `manifestid` | string | OID of the manifest blob built during the last refresh |

---

### File F2: Codemap

**Path:** `.permguard/code/@workspace/codemap`
**Format:** CSV (no header row)
**Written by:** `SaveCodeSourceCodeMap()` during blobification (Step 2)
**Read by:** `ReadCodeSourceCodeMap()` during validation and pull materialization

Maps source files to their parsed blob objects. A file with 3 policies produces 3 rows.

| Col | Field | Type | Example | Description |
|:---:|-------|------|---------|-------------|
| 0 | Path | string | `./policies.cedar` | Relative path to source file |
| 1 | OID | string | `bafyrei...abc` | Blob OID (empty if parsing error) |
| 2 | OType | string | `blob` | Object type |
| 3 | OName | string | `allow-read` | Object name (= policy/schema name) |
| 4 | CodeID | string | `allow-read` | Code identifier |
| 5 | CodeTypeID | uint32 | `2` | `1`=schema, `2`=policy |
| 6 | LanguageID | uint32 | `2` | `1`=cedar, `2`=cedar-json |
| 7 | LanguageVersionID | uint32 | `0` | Language version |
| 8 | LanguageTypeID | uint32 | `2` | `1`=schema, `2`=policy |
| 9 | Mode | uint32 | `420` | File permission mode |
| 10 | Section | int | `0` | Section index (0-based) |
| 11 | HasErrors | bool | `false` | Whether parsing failed |
| 12 | Error | string | _(empty)_ | Error message if failed |

**Key difference from codestate:** includes file-level info (Path, Mode, Section, HasErrors, Error) needed for error reporting and file regeneration.

---

### File F3: Codestate

**Path:** `.permguard/code/@workspace/codestate`
**Format:** CSV (no header row)
**Written by:** `SaveCodeSourceCodeState()` during blobification (Step 4)
**Read by:** `ReadCodeSourceCodeState()` during plan calculation

One row per code object in the local tree. State is empty (filled during plan).
**Note:** The manifest is NOT stored in this file. It is added dynamically during plan calculation from the COSP config.

| Col | Field | Type | Example | Description |
|:---:|-------|------|---------|-------------|
| 0 | State | string | _(empty)_ | Not set yet (set during plan) |
| 1 | Partition | string | `/` | Partition path |
| 2 | OName | string | `allow-read` | Object name (comparison key) |
| 3 | OType | string | `blob` | Object type |
| 4 | OID | string | `bafyrei...abc` | Blob OID (compared for changes) |
| 5 | CodeID | string | `allow-read` | Code identifier |
| 6 | CodeTypeID | uint32 | `2` | Code type |
| 7 | LanguageID | uint32 | `2` | Language |
| 8 | LanguageVersionID | uint32 | `0` | Language version |
| 9 | LanguageTypeID | uint32 | `2` | Language type |

**Key difference from codemap:** no file-level fields. Only object-level fields used for tree comparison.

**Note:** The `DataType` field from `CodeObjectState` is NOT persisted in the CSV. This is why the manifest entry (which requires `DataType=TreeDataTypeManifest` to be correctly skipped during tree building) is managed in-memory only.

---

### File F4: Plan

**Path:** `.permguard/code/{ref}/plan`
**Format:** CSV (no header row)
**Written by:** `SaveRemoteCodePlan()` during plan calculation
**Read by:** `ReadRemoteCodePlan()` during apply

Same structure as codestate, but with State filled after comparison.
Includes both code objects and the manifest entry.

| Col | Field | Type | Example | Description |
|:---:|-------|------|---------|-------------|
| 0 | State | string | `create` | `create`, `modify`, `delete`, `unchanged` |
| 1 | Partition | string | `/` | Partition path |
| 2 | OName | string | `allow-read` | Object name |
| 3 | OType | string | `blob` | Object type |
| 4 | OID | string | `bafyrei...abc` | Blob OID |
| 5 | CodeID | string | `allow-read` | Code identifier |
| 6 | CodeTypeID | uint32 | `2` | Code type |
| 7 | LanguageID | uint32 | `2` | Language |
| 8 | LanguageVersionID | uint32 | `0` | Language version |
| 9 | LanguageTypeID | uint32 | `2` | Language type |

**State values:**

| State | Meaning |
|-------|---------|
| `unchanged` | Same OName, same OID in local and remote |
| `create` | Exists in local, not in remote |
| `modify` | Same OName, different OID |
| `delete` | Exists in remote, not in local |

The manifest entry uses `OName="manifest"` and appears with states like any other entry (e.g. `modify` when switching from JSON to YAML format).

---

### File F5: Manifest

**Path:** `manifest.json`, `manifest.yaml`, or `manifest.yml` (workspace root, only one allowed)
**Format:** JSON or YAML (must match file extension)
**Read by:** `hasValidManifestWorkspaceDir()` at the start of every operation via `DetectManifestFile()`

**JSON example:**
```json
{
  "metadata": {
    "name": "my-workspace",
    "description": "...",
    "author": "...",
    "license": "..."
  },
  "runtimes": {
    "cedar": {
      "language": { "name": "cedar", "version": ">=0.0.0" },
      "engine": { "name": "permguard", "version": ">=0.0.0", "distribution": "community" }
    }
  },
  "ztas_app": [
    {
      "partitions": {
        "/": { "runtime": "cedar", "schema": false }
      }
    }
  ]
}
```

**YAML example:**
```yaml
metadata:
  name: my-workspace
  description: ""
  author: ""
  license: ""
runtimes:
  cedar:
    language:
      name: cedar
      version: ">=0.0.0"
    engine:
      name: permguard
      version: ">=0.0.0"
      distribution: community
ztas_app:
  - partitions:
      /:
        runtime: cedar
        schema: false
```

| Section | Description |
|---------|-------------|
| `metadata` | Workspace name, description, author, license |
| `runtimes` | Named runtime configs, each with language + engine |
| `ztas_app[].partitions` | Map of partition path -> runtime reference |

A partition maps to one runtime, which maps to one language.

**Schema flag behavior:**

| `schema` value | Schema file exists | Result |
|----------------|-------------------|--------|
| `true` | Yes | Blobified normally |
| `true` | No | **Error**: schema file is required |
| `false` | Yes | Blobified normally (preserved for future re-enable) |
| `false` | No | Silently skipped (no error) |

---

### File F6: HEAD Pointer

**Path:** `.permguard/refs/heads`
**Format:** TOML

```toml
[reference]
ref = "heads/permguard/1/my-ledger"
```

Points to the current active ref (ledger branch).

---

### File F7: Ref Config

**Path:** `.permguard/refs/{zone}/{ledger}/{ref}/config`
**Format:** TOML

```toml
[objects]
upstreamref = "heads/permguard/1/my-ledger"
ledgerid = "uuid-of-ledger"
commit = "bafyrei..."
```

| Field | Description |
|-------|-------------|
| `upstreamref` | The upstream reference name |
| `ledgerid` | UUID of the ledger on the server |
| `commit` | OID of the last known commit for this ref |

---

### File F8: Remote Definition

**Path:** `.permguard/refs/remote`
**Format:** TOML

```toml
[remote]
name = "origin"
server = "localhost"
zapport = 5554
papport = 5555
scheme = "grpc"
```

| Field | Description |
|-------|-------------|
| `name` | Remote name (e.g. "origin") |
| `server` | Server hostname |
| `zapport` | ZAP service port (zone admin) |
| `papport` | PAP service port (policy admin) |
| `scheme` | Connection scheme (`grpc`) |

---

### File F9: Object Store

**Path:** `.permguard/objs/XX/...rest_of_oid` (remote store)
**Path:** `.permguard/code/@workspace/objs/XX/...rest_of_oid` (local store)
**Format:** Raw binary (CBOR envelope)

Objects are sharded by the **last 2 characters** of the OID for filesystem performance.

Example: OID `bafyreia515513cd9200cfe899da7ac17a2293ed23a35674b933010d9736e634`
-> stored at `objs/34/bafyreia515513cd9200cfe899da7ac17a2293ed23a35674b933010d9736e6`

| Store | Location | Lifecycle |
|-------|----------|-----------|
| Local (`@workspace/objs/`) | Blobs + tree from current blobification | Rebuilt on every refresh, deleted after push |
| Remote (`objs/`) | Commits + trees + blobs from server | Persisted across sessions, updated on pull |

---

## Part 5: Internal Data Structures

### SectionObject

Returned by the language abstraction when parsing a source file. One per policy/schema entry.

```go
type SectionObject struct {
    obj       *Object         // Serialized CBOR blob (nil on error)
    partition string          // Partition path
    otype     string          // "blob"
    oname     string          // Object name (e.g. "allow-read")
    metadata  map[string]any  // {code-id, code-type-id, language-id, ...}
    numOfSect int             // Section index (0-based)
    err       error           // Parsing error (nil if OK)
}
```

### MultiSectionsObject

Container for all sections from a single source file.

```go
type MultiSectionsObject struct {
    path        string             // Source file path
    objSections []*SectionObject   // Parsed sections
    numOfSects  int                // Expected number of sections
    err         error              // File-level error
}
```

### CodeFile

One parsed section after blobification, enriched with file metadata. Stored in codemap CSV.

```go
type CodeFile struct {
    Kind              string  // "code" or "schema"
    Partition         string  // Partition path
    Path              string  // Relative file path
    OID               string  // Blob OID (empty on error)
    OType             string  // "blob"
    OName             string  // Object name
    CodeID            string  // Code identifier
    CodeTypeID        uint32  // 1=schema, 2=policy
    LanguageID        uint32  // Language identifier
    LanguageVersionID uint32  // Language version
    LanguageTypeID    uint32  // Language type
    Mode              uint32  // File permission mode
    Section           int     // Section index (0-based)
    HasErrors         bool    // Whether parsing failed
    Error             string  // Error message
}
```

### CodeObject / CodeObjectState

Object-level representation for tree comparison. Stored in codestate and plan CSVs.

```go
type CodeObject struct {
    Partition         string  // Partition path
    OName             string  // Object name (comparison key)
    OType             string  // "blob"
    OID               string  // Blob OID (compared for changes)
    DataType          uint32  // Tree entry data type (not persisted in CSV)
    CodeID            string
    CodeTypeID        uint32
    LanguageID        uint32
    LanguageTypeID    uint32
    LanguageVersionID uint32
}

type CodeObjectState struct {
    CodeObject
    State string  // "", "unchanged", "create", "modify", "delete"
}
```

**Note:** `DataType` is not serialized to CSV. For manifest entries added dynamically during plan, `DataType` is set to `TreeDataTypeManifest` in memory so `buildPlanTree` can skip them.

### ManifestLanguageProvider

Built from the manifest file at the start of every operation.

```go
type ManifestLanguageProvider struct {
    manifest  *Manifest
    langInfos map[string]languageInfo  // partitionKey -> { lang, langAbs, schemaEnabled }
}
```

Key methods:

| Method | Returns | Description |
|--------|---------|-------------|
| `Partitions()` | `[]string` | All partition keys |
| `Language(partition)` | `*Language` | Language config for partition |
| `AbstractLanguage(partition)` | `LanguageAbstraction` | Language abstraction for partition |
| `SchemaEnabled(partition)` | `bool` | Whether schema is required for partition |

### LanguageAbstraction (interface)

Key methods called by the workspace:

| Method | Used in | Returns |
|--------|---------|---------|
| `PolicyFileExtensions()` | Scanning | `[".cedar"]` |
| `SchemaFileNames()` | Scanning | `["permguard.schema"]` |
| `CreatePolicyBlobObjects()` | Blobification | MultiSectionsObject |
| `CreateSchemaBlobObjects()` | Blobification | MultiSectionsObject |
| `ConvertBytesToHumanLanguage()` | Pull, `--human` | Human-readable bytes |
| `CreatePolicyContentBytes()` | Pull | Merged policy file |
| `CreateSchemaContentBytes()` | Pull | Schema file |
| `ValidateManifest()` | Init/refresh | bool |
