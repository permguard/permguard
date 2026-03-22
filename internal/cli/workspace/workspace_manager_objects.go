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
	"strconv"
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
func derefParent(p *string) string {
	if p == nil {
		return ""
	}
	return *p
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
			"  - Committer date: %s\n"+
			"  - Author date: %s",
		common.KeywordText("commit"),
		common.IDText(oid),
		common.KeywordText("tree"),
		common.IDText(tree),
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
	output["tree"] = commit.Tree()
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
			e.Type(),
			e.Partition(),
			e.OName(),
			m.resolveLanguageID(e.LanguageID()),
			m.resolveLanguageVersionID(e.LanguageID(), e.LanguageVersionID()),
			m.resolveLanguageTypeID(e.LanguageTypeID()),
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
	fmt.Fprintf(&sb, "  %s\n", tableHeader(headers, widths, nil))
	for _, row := range dataRows {
		fmt.Fprintf(&sb, "  %s\n", tableRow(row, widths, colorFns, nil))
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
			"type":             entry.Type(),
			"partition":        entry.Partition(),
			"language":         m.resolveLanguageID(entry.LanguageID()),
			"language_version": m.resolveLanguageVersionID(entry.LanguageID(), entry.LanguageVersionID()),
			"language_type":    m.resolveLanguageTypeID(entry.LanguageTypeID()),
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
// alignRight controls per-column alignment: true = right-align, false (or nil) = left-align.
func tableRow(vals []string, widths []int, colorFns []func(string) string, alignRight []bool) string {
	var sb strings.Builder
	for i, v := range vals {
		right := i < len(alignRight) && alignRight[i]
		var padded string
		if right {
			padded = fmt.Sprintf("%*s", widths[i], v)
		} else {
			padded = fmt.Sprintf("%-*s", widths[i], v)
		}
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
// alignRight controls per-column alignment: true = right-align, false (or nil) = left-align.
func tableHeader(headers []string, widths []int, alignRight []bool) string {
	var sb strings.Builder
	for i, h := range headers {
		right := i < len(alignRight) && alignRight[i]
		if i < len(headers)-1 {
			if right {
				fmt.Fprintf(&sb, "%*s  ", widths[i], h)
			} else {
				fmt.Fprintf(&sb, "%-*s  ", widths[i], h)
			}
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
	headers := []string{"TREE", "PARENT", "AUTHOR", "AUTHOR-TS", "COMMITTER", "COMMITTER-TS", "MESSAGE"}
	dataRow := []string{
		commit.Tree(),
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
		common.NameText,
		common.TimeStampText,
		common.NameText,
		common.TimeStampText,
		common.NormalText,
	}

	var sb strings.Builder
	sb.WriteString(m.objectInspectHeader(oid, "commit", sizeBytes))
	fmt.Fprintf(&sb, "  %s\n", tableHeader(headers, widths, nil))
	fmt.Fprintf(&sb, "  %s", tableRow(dataRow, widths, colorFns, nil))
	return sb.String(), nil
}

// treeTableString formats a tree object as an aligned inspect table with all CBOR fields.
// First row is the tree object itself (TYPE=tree, OID=tree OID).
// Subsequent rows are the tree entries (one per cborTreeEntry).
// Columns: TYPE | PARTITION | OID | ONAME | CODE-ID | CODE-TYPE-ID | CODE-TYPE | LANG-ID | LANGUAGE | LANG-VERSION-ID | LANG-VERSION | LANG-TYPE-ID | LANG-TYPE
func (m *Manager) treeTableString(oid string, tree *objects.Tree, sizeBytes int) (string, error) {
	if tree == nil {
		return "", errors.New("cli: tree is nil")
	}

	headers := []string{"TYPE", "PARTITION", "OID", "ONAME", "CODE-ID", "CODE-TYPE-ID", "CODE-TYPE", "LANG-ID", "LANGUAGE", "LANG-VERSION-ID", "LANG-VERSION", "LANG-TYPE-ID", "LANG-TYPE"}

	// First row: the tree object itself.
	selfRow := []string{"tree", "", oid, "", "", "", "", "", "", "", "", "", ""}

	entries := tree.Entries()
	dataRows := make([][]string, 0, 1+len(entries))
	dataRows = append(dataRows, selfRow)
	for _, e := range entries {
		langVerID := strconv.FormatUint(uint64(e.LanguageVersionID()), 10)
		langVer := m.resolveLanguageVersionID(e.LanguageID(), e.LanguageVersionID())
		if e.LanguageVersionID() == 0 {
			langVerID = ""
			langVer = ""
		}
		dataRows = append(dataRows, []string{
			e.Type(),
			e.Partition(),
			e.OID(),
			e.OName(),
			e.CodeID(),
			strconv.FormatUint(uint64(e.CodeTypeID()), 10),
			m.resolveCodeTypeID(e.CodeTypeID()),
			strconv.FormatUint(uint64(e.LanguageID()), 10),
			m.resolveLanguageID(e.LanguageID()),
			langVerID,
			langVer,
			strconv.FormatUint(uint64(e.LanguageTypeID()), 10),
			m.resolveLanguageTypeID(e.LanguageTypeID()),
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
		common.KeywordText,
		common.LanguageText,
		common.LanguageText,
		common.LanguageText,
		common.LanguageText,
		common.LanguageKeywordText,
		common.LanguageKeywordText,
	}

	// TYPE PARTITION OID ONAME CODE-ID CODE-TYPE-ID CODE-TYPE LANG-ID LANGUAGE LANG-VERSION-ID LANG-VERSION LANG-TYPE-ID LANG-TYPE
	alignRight := []bool{false, false, false, false, false, true, false, true, false, true, false, true, false}

	var sb strings.Builder
	sb.WriteString(m.objectInspectHeader(oid, "tree", sizeBytes))
	fmt.Fprintf(&sb, "  %s\n", tableHeader(headers, widths, alignRight))
	for _, row := range dataRows {
		fmt.Fprintf(&sb, "  %s\n", tableRow(row, widths, colorFns, alignRight))
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
		"tree":                commit.Tree(),
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
			"type":             e.Type(),
			"partition":        e.Partition(),
			"oid":              e.OID(),
			"oname":            e.OName(),
			"code_id":          e.CodeID(),
			"code_type_id":     e.CodeTypeID(),
			"code_type":        m.resolveCodeTypeID(e.CodeTypeID()),
			"language_id":      e.LanguageID(),
			"language":         m.resolveLanguageID(e.LanguageID()),
			"language_type_id": e.LanguageTypeID(),
			"language_type":    m.resolveLanguageTypeID(e.LanguageTypeID()),
		}
		entry["language_version_id"] = e.LanguageVersionID()
		entry["language_version"] = m.resolveLanguageVersionID(e.LanguageID(), e.LanguageVersionID())
		allEntries = append(allEntries, entry)
	}
	return map[string]any{"entries": allEntries}, nil
}

// blobInspectMap returns all CBOR fields of a blob as a map for JSON output.
// The "data" field contains the raw blob bytes encoded as base64.
func (m *Manager) blobInspectMap(objInfo objects.ObjectInfo) (map[string]any, error) {
	header := objInfo.Header()
	if header == nil {
		return nil, errors.New("cli: blob header is nil")
	}
	data, _ := objInfo.Instance().([]byte)
	result := map[string]any{
		"partition":          header.Partition(),
		"is_native_language": header.IsNativeLanguage(),
		"language_id":        header.LanguageID(),
		"language":           m.resolveLanguageID(header.LanguageID()),
		"language_type_id":   header.LanguageTypeID(),
		"language_type":      m.resolveLanguageTypeID(header.LanguageTypeID()),
		"code_type_id":       header.CodeTypeID(),
		"code_type":          m.resolveCodeTypeID(header.CodeTypeID()),
		"code_id":            header.CodeID(),
		"data":               base64.StdEncoding.EncodeToString(data),
	}
	result["language_version_id"] = header.LanguageVersionID()
	result["language_version"] = m.resolveLanguageVersionID(header.LanguageID(), header.LanguageVersionID())
	return result, nil
}

// blobTableString formats a blob object as an aligned inspect table with all CBOR fields.
// Columns: PARTITION | IS-NATIVE | LANG-ID | LANGUAGE | LANG-VERSION-ID | LANG-VERSION | LANG-TYPE-ID | LANG-TYPE | CODE-TYPE-ID | CODE-TYPE | CODE-ID | DATA (base64)
func (m *Manager) blobTableString(objInfo objects.ObjectInfo, sizeBytes int) (string, error) {
	header := objInfo.Header()
	if header == nil {
		return "", errors.New("cli: blob header is nil")
	}

	langVerID := strconv.FormatUint(uint64(header.LanguageVersionID()), 10)
	langVer := m.resolveLanguageVersionID(header.LanguageID(), header.LanguageVersionID())
	if header.LanguageVersionID() == 0 {
		langVerID = ""
		langVer = ""
	}

	data, _ := objInfo.Instance().([]byte)
	headers := []string{"PARTITION", "IS-NATIVE", "LANG-ID", "LANGUAGE", "LANG-VERSION-ID", "LANG-VERSION", "LANG-TYPE-ID", "LANG-TYPE", "CODE-TYPE-ID", "CODE-TYPE", "CODE-ID", "DATA"}
	dataRow := []string{
		header.Partition(),
		strconv.FormatBool(header.IsNativeLanguage()),
		strconv.FormatUint(uint64(header.LanguageID()), 10),
		m.resolveLanguageID(header.LanguageID()),
		langVerID,
		langVer,
		strconv.FormatUint(uint64(header.LanguageTypeID()), 10),
		m.resolveLanguageTypeID(header.LanguageTypeID()),
		strconv.FormatUint(uint64(header.CodeTypeID()), 10),
		m.resolveCodeTypeID(header.CodeTypeID()),
		header.CodeID(),
		base64.StdEncoding.EncodeToString(data),
	}
	widths := columnWidths(headers, [][]string{dataRow})

	colorFns := []func(string) string{
		common.NameText,
		common.KeywordText,
		common.LanguageText,
		common.LanguageText,
		common.LanguageText,
		common.LanguageText,
		common.LanguageKeywordText,
		common.LanguageKeywordText,
		common.KeywordText,
		common.KeywordText,
		common.NameText,
		common.NormalText,
	}

	// PARTITION IS-NATIVE LANG-ID LANGUAGE LANG-VERSION-ID LANG-VERSION LANG-TYPE-ID LANG-TYPE CODE-TYPE-ID CODE-TYPE CODE-ID DATA
	alignRight := []bool{false, false, true, false, true, false, true, false, true, false, false, false}

	var sb strings.Builder
	sb.WriteString(m.objectInspectHeader(objInfo.OID(), "blob", sizeBytes))
	fmt.Fprintf(&sb, "  %s\n", tableHeader(headers, widths, alignRight))
	fmt.Fprintf(&sb, "  %s", tableRow(dataRow, widths, colorFns, alignRight))
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
