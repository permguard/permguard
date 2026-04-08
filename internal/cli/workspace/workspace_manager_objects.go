// Copyright 2024 Nitro Agility S.r.l.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"

	"github.com/permguard/permguard/internal/cli/common"
	azwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
)

// objectsInfos retrieves and filters object metadata based on object type.
func (m *Manager) objectsInfos(includeStorage, includeCode, filterCommits, filterTrees, filterBlob bool) ([]objects.ObjectInfo, error) {
	var filteredObjects []objects.ObjectInfo

	// Fetch all raw objs from the COSP manager
	objs, err := m.cospMgr.Objects(includeStorage, includeCode)
	if err != nil {
		return nil, err
	}
	if len(objs) == 0 {
		return filteredObjects, nil
	}

	// Initialize the object manager
	objMgr, err := objects.NewObjectManager()
	if err != nil {
		return nil, err
	}

	// Iterate and filter objs by type
	for _, object := range objs {
		objInfo, err := objMgr.ObjectInfo(&object)
		if err != nil {
			return nil, err
		}

		switch objInfo.Type() {
		case objects.ObjectTypeCommit:
			if !filterCommits {
				continue
			}
		case objects.ObjectTypeTree:
			if !filterTrees {
				continue
			}
		case objects.ObjectTypeBlob:
			if !filterBlob {
				continue
			}
		}

		filteredObjects = append(filteredObjects, *objInfo)
	}

	return filteredObjects, nil
}

// derefParent returns the dereferenced parent OID or an empty string for a root commit.
func derefParent(p objects.NullableString) string {
	if !p.Valid {
		return ""
	}
	return p.String
}

// history gets the commit history.
func (m *Manager) history(commit string) ([]azwkscommon.CommitInfo, error) {
	commitHistory, err := m.cospMgr.History(commit)
	if err != nil {
		return nil, err
	}
	return commitHistory, nil
}

// commitString gets the commit string.
func (m *Manager) commitString(oid string, commit *objects.Commit) (string, error) {
	if commit == nil {
		return "", errors.New("cli: commit is nil")
	}

	tree := commit.Tree()
	metadata := commit.MetaData()
	committerTimestamp := metadata.CommitterTimestamp()
	authorTimestamp := metadata.AuthorTimestamp()

	output := fmt.Sprintf(
		"%s %s:\n"+
			"  - %s: %s\n"+
			"  - %s: %s\n"+
			"  - Committer date: %s\n"+
			"  - Author date: %s",
		common.KeywordText("commit"),
		common.IDText(oid),
		common.KeywordText("tree"),
		common.IDText(tree.String()),
		common.KeywordText("manifest"),
		common.IDText(commit.Manifest().String()),
		common.DateText(committerTimestamp),
		common.DateText(authorTimestamp),
	)
	return output, nil
}

// commitMap gets the commit map.
func (m *Manager) commitMap(oid string, commit *objects.Commit) (map[string]any, error) {
	if commit == nil {
		return nil, errors.New("cli: commit is nil")
	}

	output := make(map[string]any)
	output["oid"] = oid
	output["parent"] = derefParent(commit.Parent())
	output["tree"] = commit.Tree().String()
	output["manifest"] = commit.Manifest().String()
	output["message"] = commit.Message()

	metdata := commit.MetaData()
	output["author"] = metdata.Author()
	output["author_timestamp"] = metdata.AuthorTimestamp()
	output["committer"] = metdata.Committer()
	output["committer_timestamp"] = metdata.CommitterTimestamp()
	return output, nil
}

// treeString gets the tree string.
func (m *Manager) treeString(oid string, tree *objects.Tree) (string, error) {
	if tree == nil {
		return "", errors.New("cli: tree is nil")
	}

	headers := []string{"OID", "TYPE", "PARTITION", "ONAME", "LANGUAGE", "LANG-VERSION", "LANG-TYPE"}

	entries := tree.Entries()
	dataRows := make([][]string, len(entries))
	for i, e := range entries {
		dataRows[i] = []string{
			e.OID(),
			e.OType(),
			tree.Partition(),
			e.OName(),
			m.resolveLanguageID(e.MetadataUint32(objects.MetaKeyLanguageID)),
			m.resolveLanguageVersionID(e.MetadataUint32(objects.MetaKeyLanguageID), e.MetadataUint32(objects.MetaKeyLanguageVersionID)),
			m.resolveLanguageTypeID(e.MetadataUint32(objects.MetaKeyLanguageTypeID)),
		}
	}
	widths := columnWidths(headers, dataRows)

	colorFns := []func(string) string{
		common.IDText,
		common.KeywordText,
		common.NameText,
		common.NameText,
		common.LanguageText,
		common.LanguageText,
		common.LanguageKeywordText,
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s:\n", common.KeywordText("tree"), common.IDText(oid))
	if len(entries) == 0 {
		fmt.Fprintf(&sb, "  (no entries)")
		return sb.String(), nil
	}
	fmt.Fprintf(&sb, "  %s\n", tableHeader(headers, widths))
	for _, row := range dataRows {
		fmt.Fprintf(&sb, "  %s\n", tableRow(row, widths, colorFns))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

// treeMap gets the tree map.
func (m *Manager) treeMap(oid string, tree *objects.Tree) (map[string]any, error) {
	if tree == nil {
		return nil, errors.New("cli: tree is nil")
	}

	output := make(map[string]any)
	output["oid"] = oid

	entries := tree.Entries()
	entriesList := make([]map[string]any, len(entries))

	for i, entry := range entries {
		entriesList[i] = map[string]any{
			"oid":              entry.OID(),
			"oname":            entry.OName(),
			"type":             entry.OType(),
			"partition":        tree.Partition(),
			"language":         m.resolveLanguageID(entry.MetadataUint32(objects.MetaKeyLanguageID)),
			"language_version": m.resolveLanguageVersionID(entry.MetadataUint32(objects.MetaKeyLanguageID), entry.MetadataUint32(objects.MetaKeyLanguageVersionID)),
			"language_type":    m.resolveLanguageTypeID(entry.MetadataUint32(objects.MetaKeyLanguageTypeID)),
		}
	}

	output["entries"] = entriesList
	return output, nil
}

// blobString gets the blob string.
func (m *Manager) blobString(blob any) ([]byte, bool, error) {
	if blob == nil {
		return nil, false, errors.New("cli: tree is nil")
	}
	content, hasContent := blob.([]byte)
	if !hasContent {
		return nil, false, errors.New("cli: blob content is not a byte array")
	}
	return content, true, nil
}

// objectDiskSizeKB returns the on-disk file size in KB for the given OID.
// Falls back to sizeBytes if the file cannot be stat'd.
func (m *Manager) objectDiskSizeKB(fullPath string, sizeBytes int) float64 {
	if info, err := os.Stat(fullPath); err == nil {
		return float64(info.Size()) / 1024.0
	}
	return float64(sizeBytes) / 1024.0
}

// objectInspectHeader returns a formatted header block for the --inspect table view.
// Shows the filename, full absolute path, and size in KB of the object on disk.
func (m *Manager) objectInspectHeader(oid, objectType string, sizeBytes int) string {
	fullPath, err := m.cospMgr.ObjectAbsolutePath(oid)
	if err != nil {
		fullPath = ""
	}
	// Reconstruct the full filename: the file on disk is oid[:len-2] inside a shard folder oid[len-2:].
	// Appending the shard folder name to the base filename gives back the complete OID string.
	name := filepath.Base(fullPath) + filepath.Base(filepath.Dir(fullPath))
	sizeKB := m.objectDiskSizeKB(fullPath, sizeBytes)
	var sb strings.Builder
	fmt.Fprintf(&sb, "  %-8s %s\n", "type", common.KeywordText(objectType))
	fmt.Fprintf(&sb, "  %-8s %s\n", "name", common.NameText(name))
	fmt.Fprintf(&sb, "  %-8s %s\n", "path", common.FileText(fullPath))
	fmt.Fprintf(&sb, "  %-8s %.2f KB\n", "size", sizeKB)
	sb.WriteString("\n")
	return sb.String()
}

// objectInspectHeaderMap returns a map with header metadata for the --inspect JSON output.
func (m *Manager) objectInspectHeaderMap(oid, objectType string, sizeBytes int) map[string]any {
	fullPath, err := m.cospMgr.ObjectAbsolutePath(oid)
	if err != nil {
		fullPath = ""
	}
	// Reconstruct the full filename: the file on disk is oid[:len-2] inside a shard folder oid[len-2:].
	// Appending the shard folder name to the base filename gives back the complete OID string.
	name := filepath.Base(fullPath) + filepath.Base(filepath.Dir(fullPath))
	sizeKB := m.objectDiskSizeKB(fullPath, sizeBytes)
	return map[string]any{
		"oid":     oid,
		"type":    objectType,
		"name":    name,
		"path":    fullPath,
		"size_kb": sizeKB,
	}
}

// resolveLanguageID converts a language uint32 ID to its display name via the registry.
func (m *Manager) resolveLanguageID(id uint32) string {
	return m.langReg.ResolveLanguageName(id)
}

// resolveLanguageVersionID converts a language version uint32 ID to its display string
// within the context of the given language ID, via the registry.
func (m *Manager) resolveLanguageVersionID(langID, versionID uint32) string {
	return m.langReg.ResolveVersionName(langID, versionID)
}

// resolveLanguageTypeID converts a language type uint32 ID to its display name via the registry.
func (m *Manager) resolveLanguageTypeID(id uint32) string {
	return m.langReg.ResolveTypeName(id)
}

// resolveCodeTypeID converts a code type uint32 ID to its display name via the registry.
func (m *Manager) resolveCodeTypeID(id uint32) string {
	return m.langReg.ResolveCodeTypeName(id)
}

// tableRow builds a padded, colored row string from raw values, widths and color functions.
func tableRow(vals []string, widths []int, colorFns []func(string) string) string {
	var sb strings.Builder
	for i, v := range vals {
		padded := fmt.Sprintf("%-*s", widths[i], v)
		colored := colorFns[i](padded)
		if i < len(vals)-1 {
			fmt.Fprintf(&sb, "%s  ", colored)
		} else {
			fmt.Fprintf(&sb, "%s", colored)
		}
	}
	return sb.String()
}

// tableHeader builds a padded header row from headers and widths.
func tableHeader(headers []string, widths []int) string {
	var sb strings.Builder
	for i, h := range headers {
		if i < len(headers)-1 {
			fmt.Fprintf(&sb, "%-*s  ", widths[i], h)
		} else {
			fmt.Fprintf(&sb, "%s", h)
		}
	}
	return sb.String()
}

// columnWidths computes per-column widths as the max of header and all row values.
func columnWidths(headers []string, rows [][]string) []int {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, v := range row {
			if i < len(widths) && len(v) > widths[i] {
				widths[i] = len(v)
			}
		}
	}
	return widths
}

// commitTableString formats a commit object as an aligned inspect table with all CBOR fields.
// Columns: TREE | PARENT | AUTHOR | AUTHOR-TS | COMMITTER | COMMITTER-TS | MESSAGE
func (m *Manager) commitTableString(oid string, commit *objects.Commit, sizeBytes int) (string, error) {
	if commit == nil {
		return "", errors.New("cli: commit is nil")
	}

	meta := commit.MetaData()
	headers := []string{"TREE", "MANIFEST", "PARENT", "AUTHOR", "AUTHOR-TS", "COMMITTER", "COMMITTER-TS", "MESSAGE"}
	dataRow := []string{
		commit.Tree().String(),
		commit.Manifest().String(),
		derefParent(commit.Parent()),
		meta.Author(),
		meta.AuthorTimestamp().UTC().Format("2006-01-02T15:04:05Z"),
		meta.Committer(),
		meta.CommitterTimestamp().UTC().Format("2006-01-02T15:04:05Z"),
		commit.Message(),
	}
	widths := columnWidths(headers, [][]string{dataRow})

	colorFns := []func(string) string{
		common.IDText,
		common.IDText,
		common.IDText,
		common.NameText,
		common.TimeStampText,
		common.NameText,
		common.TimeStampText,
		common.NormalText,
	}

	var sb strings.Builder
	sb.WriteString(m.objectInspectHeader(oid, "commit", sizeBytes))
	fmt.Fprintf(&sb, "  %s\n", tableHeader(headers, widths))
	fmt.Fprintf(&sb, "  %s", tableRow(dataRow, widths, colorFns))
	return sb.String(), nil
}

// treeTableString formats a tree object as an aligned inspect table with resolved names only.
// First row is the tree object itself (TYPE=tree, OID=tree OID).
// Subsequent rows are the tree entries (one per cborTreeEntry).
// Columns: TYPE | PARTITION | OID | ONAME | CODE-ID | CODE-TYPE | LANGUAGE | LANG-VERSION | LANG-TYPE
func (m *Manager) treeTableString(oid string, tree *objects.Tree, sizeBytes int) (string, error) {
	if tree == nil {
		return "", errors.New("cli: tree is nil")
	}

	headers := []string{"TYPE", "PARTITION", "OID", "ONAME", "CODE-ID", "CODE-TYPE", "LANGUAGE", "LANG-VERSION", "LANG-TYPE"}

	// First row: the tree object itself.
	selfRow := []string{"tree", "", oid, "", "", "", "", "", ""}

	entries := tree.Entries()
	dataRows := make([][]string, 0, 1+len(entries))
	dataRows = append(dataRows, selfRow)
	for _, e := range entries {
		codeType := ""
		if e.MetadataUint32(objects.MetaKeyCodeTypeID) != 0 {
			codeType = m.resolveCodeTypeID(e.MetadataUint32(objects.MetaKeyCodeTypeID))
		}
		lang := ""
		if e.MetadataUint32(objects.MetaKeyLanguageID) != 0 {
			lang = m.resolveLanguageID(e.MetadataUint32(objects.MetaKeyLanguageID))
		}
		langVer := ""
		if e.MetadataUint32(objects.MetaKeyLanguageVersionID) != 0 {
			langVer = m.resolveLanguageVersionID(e.MetadataUint32(objects.MetaKeyLanguageID), e.MetadataUint32(objects.MetaKeyLanguageVersionID))
		}
		langType := ""
		if e.MetadataUint32(objects.MetaKeyLanguageTypeID) != 0 {
			langType = m.resolveLanguageTypeID(e.MetadataUint32(objects.MetaKeyLanguageTypeID))
		}
		dataRows = append(dataRows, []string{
			e.OType(),
			tree.Partition(),
			e.OID(),
			e.OName(),
			e.MetadataString(objects.MetaKeyCodeID),
			codeType,
			lang,
			langVer,
			langType,
		})
	}

	widths := columnWidths(headers, dataRows)

	colorFns := []func(string) string{
		common.KeywordText,
		common.NameText,
		common.IDText,
		common.NameText,
		common.NameText,
		common.KeywordText,
		common.LanguageText,
		common.LanguageText,
		common.LanguageKeywordText,
	}

	var sb strings.Builder
	sb.WriteString(m.objectInspectHeader(oid, "tree", sizeBytes))
	fmt.Fprintf(&sb, "  %s\n", tableHeader(headers, widths))
	for _, row := range dataRows {
		fmt.Fprintf(&sb, "  %s\n", tableRow(row, widths, colorFns))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

// commitInspectMap returns all CBOR fields of a commit as a map for JSON output.
func (m *Manager) commitInspectMap(_ string, commit *objects.Commit) (map[string]any, error) {
	if commit == nil {
		return nil, errors.New("cli: commit is nil")
	}
	meta := commit.MetaData()
	return map[string]any{
		"tree":                commit.Tree().String(),
		"manifest":            commit.Manifest().String(),
		"parent":              derefParent(commit.Parent()),
		"author":              meta.Author(),
		"author_timestamp":    meta.AuthorTimestamp().UTC().Format("2006-01-02T15:04:05Z"),
		"committer":           meta.Committer(),
		"committer_timestamp": meta.CommitterTimestamp().UTC().Format("2006-01-02T15:04:05Z"),
		"message":             commit.Message(),
	}, nil
}

// treeInspectMap returns all CBOR fields of a tree as a map for JSON output.
// The first entry in "entries" represents the tree object itself (type="tree").
func (m *Manager) treeInspectMap(oid string, tree *objects.Tree) (map[string]any, error) {
	if tree == nil {
		return nil, errors.New("cli: tree is nil")
	}
	entries := tree.Entries()
	allEntries := make([]map[string]any, 0, 1+len(entries))
	allEntries = append(allEntries, map[string]any{
		"type": "tree",
		"oid":  oid,
	})
	for _, e := range entries {
		entry := map[string]any{
			"type":             e.OType(),
			"partition":        tree.Partition(),
			"oid":              e.OID(),
			"oname":            e.OName(),
			"code_id":          e.MetadataString(objects.MetaKeyCodeID),
			"code_type_id":     e.MetadataUint32(objects.MetaKeyCodeTypeID),
			"code_type":        m.resolveCodeTypeID(e.MetadataUint32(objects.MetaKeyCodeTypeID)),
			"language_id":      e.MetadataUint32(objects.MetaKeyLanguageID),
			"language":         m.resolveLanguageID(e.MetadataUint32(objects.MetaKeyLanguageID)),
			"language_type_id": e.MetadataUint32(objects.MetaKeyLanguageTypeID),
			"language_type":    m.resolveLanguageTypeID(e.MetadataUint32(objects.MetaKeyLanguageTypeID)),
		}
		entry["language_version_id"] = e.MetadataUint32(objects.MetaKeyLanguageVersionID)
		entry["language_version"] = m.resolveLanguageVersionID(e.MetadataUint32(objects.MetaKeyLanguageID), e.MetadataUint32(objects.MetaKeyLanguageVersionID))
		allEntries = append(allEntries, entry)
	}
	return map[string]any{"entries": allEntries}, nil
}

// blobInspectMap returns all CBOR fields of a blob as a map for JSON output.
// The layout varies by data type: manifest blobs show only data type info,
// while code blobs include both raw IDs and resolved text names.
func (m *Manager) blobInspectMap(objInfo objects.ObjectInfo) (map[string]any, error) {
	header := objInfo.Header()
	if header == nil {
		return nil, errors.New("cli: blob header is nil")
	}
	data, _ := objInfo.Instance().([]byte)
	result := map[string]any{
		"data_type_id":   header.DataType(),
		"data_type_name": objects.DataTypeName(header.DataType()),
		"metadata":       header.Metadata(),
		"data":           base64.StdEncoding.EncodeToString(data),
	}
	if header.DataType() != objects.DataTypeManifest {
		result["code_id"] = header.MetadataString(objects.MetaKeyCodeID)
		result["code_type_id"] = header.MetadataUint32(objects.MetaKeyCodeTypeID)
		result["code_type"] = m.resolveCodeTypeID(header.MetadataUint32(objects.MetaKeyCodeTypeID))
		result["language_id"] = header.MetadataUint32(objects.MetaKeyLanguageID)
		result["language"] = m.resolveLanguageID(header.MetadataUint32(objects.MetaKeyLanguageID))
		result["language_version_id"] = header.MetadataUint32(objects.MetaKeyLanguageVersionID)
		result["language_version"] = m.resolveLanguageVersionID(header.MetadataUint32(objects.MetaKeyLanguageID), header.MetadataUint32(objects.MetaKeyLanguageVersionID))
		result["language_type_id"] = header.MetadataUint32(objects.MetaKeyLanguageTypeID)
		result["language_type"] = m.resolveLanguageTypeID(header.MetadataUint32(objects.MetaKeyLanguageTypeID))
	}
	return result, nil
}

// blobTableString formats a blob object as an aligned inspect table with resolved names only.
// The layout varies by data type: manifest blobs show only DATA-TYPE, while code blobs
// show the full set of code-related columns.
func (m *Manager) blobTableString(objInfo objects.ObjectInfo, sizeBytes int) (string, error) {
	header := objInfo.Header()
	if header == nil {
		return "", errors.New("cli: blob header is nil")
	}

	var headers []string
	var dataRow []string
	var colorFns []func(string) string

	switch header.DataType() {
	case objects.DataTypeManifest:
		headers = []string{"DATA-TYPE"}
		dataRow = []string{
			objects.DataTypeName(header.DataType()),
		}
		colorFns = []func(string) string{
			common.KeywordText,
		}
	default:
		langVer := m.resolveLanguageVersionID(header.MetadataUint32(objects.MetaKeyLanguageID), header.MetadataUint32(objects.MetaKeyLanguageVersionID))
		if header.MetadataUint32(objects.MetaKeyLanguageVersionID) == 0 {
			langVer = ""
		}
		headers = []string{"DATA-TYPE", "CODE-ID", "CODE-TYPE", "LANGUAGE", "LANG-VERSION", "LANG-TYPE"}
		dataRow = []string{
			objects.DataTypeName(header.DataType()),
			header.MetadataString(objects.MetaKeyCodeID),
			m.resolveCodeTypeID(header.MetadataUint32(objects.MetaKeyCodeTypeID)),
			m.resolveLanguageID(header.MetadataUint32(objects.MetaKeyLanguageID)),
			langVer,
			m.resolveLanguageTypeID(header.MetadataUint32(objects.MetaKeyLanguageTypeID)),
		}
		colorFns = []func(string) string{
			common.KeywordText,
			common.NameText,
			common.KeywordText,
			common.LanguageText,
			common.LanguageText,
			common.LanguageKeywordText,
		}
	}

	widths := columnWidths(headers, [][]string{dataRow})

	var sb strings.Builder
	sb.WriteString(m.objectInspectHeader(objInfo.OID(), "blob", sizeBytes))
	fmt.Fprintf(&sb, "  %s\n", tableHeader(headers, widths))
	fmt.Fprintf(&sb, "  %s", tableRow(dataRow, widths, colorFns))
	return sb.String(), nil
}

// getBlobString gets the blob map.
func (m *Manager) blobMap(blob any) (map[string]any, error) {
	if blob == nil {
		return nil, errors.New("cli: tree is nil")
	}
	content, hasContent := blob.([]byte)
	if !hasContent {
		return nil, errors.New("cli: blob content is not a byte array")
	}
	contentMap := make(map[string]any)
	var result map[string]any
	err := json.Unmarshal(content, &result)
	if err != nil {
		contentMap["content"] = base64.StdEncoding.EncodeToString(content)
	} else {
		contentMap["content"] = result
	}
	return contentMap, nil
}
