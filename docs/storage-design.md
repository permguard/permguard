# GitLike Storage Design & Specifications

The **Auth\*** storage is implemented as a **git-like** storage.
Here is what the history looks like:

```bash
Your workspace history head/853657895893/842b7cb8095b4fe496ef6dc0b39c98ae:

commit bafyreidbfqyp54exmsivipimux27xxuafywrtrufnhqzqaez5f2r7zfifq:
  - tree: bafyreid6ynmxy5y3edhxk7y4ohgstb7ichehamq6uo3ycvneqsvbr24fz4
  - manifest: bafyreig7lbj54eovjli534dwju3i3zce3vyldzyvdd7uvk2vtjro3xtqzy
  - Committer date: 2026-04-05 14:49:27 +0200 CEST
  - Author date: 2026-04-05 14:49:27 +0200 CEST
commit bafyreidsol7phrsmazdi4v6fcap7weik64ulamvli5ucv57q57tvxkcpse:
  - tree: bafyreieoiu62zrq32f2tvajgsydhttomuebjl6vqu6ptjukh3vzbcue6me
  - manifest: bafyreig7lbj54eovjli534dwju3i3zce3vyldzyvdd7uvk2vtjro3xtqzy
  - Committer date: 2026-04-05 14:49:20 +0200 CEST
  - Author date: 2026-04-05 14:49:20 +0200 CEST
commit bafyreig6xe6ctnx4psj5jnawnmm5gt55wasu6g6zypufuetrf6wkdwkxya:
  - tree: bafyreid6ynmxy5y3edhxk7y4ohgstb7ichehamq6uo3ycvneqsvbr24fz4
  - manifest: bafyreig7lbj54eovjli534dwju3i3zce3vyldzyvdd7uvk2vtjro3xtqzy
  - Committer date: 2026-04-05 14:48:43 +0200 CEST
  - Author date: 2026-04-05 14:48:43 +0200 CEST
```

## Commit

A commit is serialized as a single CBOR object.

| Key | Field | Type | Example | Description |
|:----:|-------|------|---------|-------------|
| `1` | `Tree` | `text` | `"bafyreid6…24fz4"` | Hash of the tree associated with the commit |
| `2` | `Parent` | `text` | `"bafyreids…cpse"` | Hash of the previous commit (`ZeroOID` for root) |
| `3` | `Author` | `text` | `""` | Commit author |
| `4` | `AuthorTimestamp` | `int` | `1743857367` | Author timestamp (Unix epoch) |
| `5` | `Committer` | `text` | `""` | Who performed the commit |
| `6` | `CommitterTimestamp` | `int` | `1743857367` | Commit timestamp (Unix epoch) |
| `7` | `Message` | `text` | `""` | Commit message |
| `8` | `Manifest` | `text` | `"bafyreig7…xtqzy"` | Hash of the manifest blob associated with the commit |

## Tree

A tree is serialized as a single CBOR object (`cborTree`) containing a partition and an array of entries. One tree = one partition.

**`cborTree`:**

| Key | Field | Type | Example | Description |
|:----:|-------|------|---------|-------------|
| `1` | `Entries` | `array` | `[…]` | Array of tree entries (see below) |
| `2` | `Partition` | `text` | `"/"` | Partition path shared by all entries |

**Each `cborTreeEntry`:**

| Key | Field | Type | Example | Description |
|:----:|-------|------|---------|-------------|
| `1` | `OType` | `text` | `"blob"` | Object type (`tree`, `blob`) |
| `2` | `OID` | `text` | `"bafyrei…3bxpi"` | CID of the referenced object |
| `3` | `OName` | `text` | `"branch-deactivate"` | Object name |
| `4` | `DataType` | `uint` | `2` | Tree entry data type (see **TreeDataType**) |
| `5` | `Metadata` | `map` | `{"code-id":"branch-deactivate", …}` | Generic metadata key-value pairs (see **Metadata Keys**) |

**Note:** The manifest blob is NOT stored as a tree entry. It is referenced directly from the commit via the `Manifest` field.

## Blob

A blob is serialized as a single CBOR object containing a data type, a generic metadata map, and the raw payload. The blob does not contain partition or profile information (those belong to the tree).

| Key | Field | Type | Example | Description |
|:----:|-------|------|---------|-------------|
| `1` | `DataType` | `uint` | `3` | Blob data type (see **DataType**) |
| `2` | `Metadata` | `map` | `{"code-id":"branch-assign-role", …}` | Generic metadata key-value pairs (see **Metadata Keys**) |
| `3` | `Data` | `bytes` | `eyJhbm5v…` | Blob payload (base64-encoded in JSON) |

**Manifest blobs** use `DataType=1` (manifest) and store `{"format":"json"}` or `{"format":"yaml"}` in metadata.
**Code blobs** use `DataType=2` (ast) or `DataType=3` (source) and store language/code metadata.

## RefData

Referential data shared across object types.

### DataType (Blob)

| ID | Name | Description |
|:----:|------|-------------|
| `0` | `unknown` | Unknown data type |
| `1` | `manifest` | Manifest data (workspace configuration) |
| `2` | `ast` | Abstract syntax tree (parsed representation) |
| `3` | `source` | Source code in the policy language |

### TreeDataType (Tree Entry)

| ID | Name | Description |
|:----:|------|-------------|
| `0` | `unknown` | Unknown tree entry type |
| `1` | `manifest` | Manifest entry (used in plan calculation, not stored in tree) |
| `2` | `policy` | Policy entry |

### Metadata Keys

Metadata is stored as a generic `map[string]any` on both blob and tree entry objects. The following well-known keys are defined:

| Key | Type | Example | Description |
|-----|------|---------|-------------|
| `partition` | `string` | `"/"` | Partition path |
| `language-id` | `uint` | `2` | Language identifier (`1` = `cedar`, `2` = `cedar-json`) |
| `language-version-id` | `uint` | `0` | Language version identifier (`0` = `0.0`) |
| `language-type-id` | `uint` | `2` | Language type identifier (`1` = `schema`, `2` = `policy`) |
| `code-id` | `string` | `"branch-deactivate"` | Code identifier |
| `code-type-id` | `uint` | `2` | Code type identifier (`1` = `schema`, `2` = `policy`) |
| `format` | `string` | `"json"` | Content format (`"json"` or `"yaml"`, used by manifest blobs) |

### CodeTypeID

| ID | Name |
|:----:|------|
| `1` | `schema` |
| `2` | `policy` |

### LanguageID

| ID | Name |
|:----:|------|
| `1` | `cedar` |
| `2` | `cedar-json` |

### LanguageVersionID

| ID | Name |
|:----:|------|
| `0` | `0.0` |

### LanguageTypeID

| ID | Name |
|:----:|------|
| `1` | `schema` |
| `2` | `policy` |
