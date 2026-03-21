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
	output["parent"] = commit.Parent()
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

	headers := []string{"OID", "TYPE", "PARTITION", "ONAME", "LANGUAGE", "VERSION", "LANG-TYPE"}

	entries := tree.Entries()
	dataRows := make([][]string, len(entries))
	for i, e := range entries {
		dataRows[i] = []string{
			e.OID(),
			e.Type(),
			e.Partition(),
			e.OName(),
			e.Language(),
			languageVersionDisplay(e.LanguageVersion()),
			e.LanguageType(),
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
		entryMap := make(map[string]any)
		entryMap["oid"] = entry.OID()
		entryMap["oname"] = entry.OName()
		entryMap["type"] = entry.Type()
		entryMap["language"] = entry.Language()
		entryMap["language_type"] = entry.LanguageType()
		entryMap["language_version"] = entry.LanguageVersion()
		entriesList[i] = entryMap
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

// languageVersionDisplay returns v, or "" when v is a zero version ("0", "0.0").
func languageVersionDisplay(v string) string {
	if v == "0" || v == "0.0" {
		return ""
	}
	return v
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

// tableHeader builds a padded header row and a separator line from headers and widths.
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
func (m *Manager) commitTableString(_ string, commit *objects.Commit) (string, error) {
	if commit == nil {
		return "", errors.New("cli: commit is nil")
	}

	meta := commit.MetaData()
	headers := []string{"TREE", "PARENT", "AUTHOR", "AUTHOR-TS", "COMMITTER", "COMMITTER-TS", "MESSAGE"}
	dataRow := []string{
		commit.Tree(),
		commit.Parent(),
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
	fmt.Fprintf(&sb, "  %s\n", tableHeader(headers, widths))
	fmt.Fprintf(&sb, "  %s", tableRow(dataRow, widths, colorFns))
	return sb.String(), nil
}

// treeTableString formats a tree object as an aligned inspect table with all CBOR fields.
// First row is the tree object itself (TYPE=tree, OID=tree OID).
// Subsequent rows are the tree entries (one per cborTreeEntry).
// Columns: TYPE | PARTITION | OID | ONAME | CODE-ID | CODE-TYPE | LANGUAGE | LANG-VERSION | LANG-TYPE
func (m *Manager) treeTableString(oid string, tree *objects.Tree) (string, error) {
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
		dataRows = append(dataRows, []string{
			e.Type(),
			e.Partition(),
			e.OID(),
			e.OName(),
			e.CodeID(),
			e.CodeType(),
			e.Language(),
			languageVersionDisplay(e.LanguageVersion()),
			e.LanguageType(),
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
		"tree":                commit.Tree(),
		"parent":              commit.Parent(),
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
		allEntries = append(allEntries, map[string]any{
			"type":             e.Type(),
			"partition":        e.Partition(),
			"oid":              e.OID(),
			"oname":            e.OName(),
			"code_id":          e.CodeID(),
			"code_type":        e.CodeType(),
			"language":         e.Language(),
			"language_version": languageVersionDisplay(e.LanguageVersion()),
			"language_type":    e.LanguageType(),
		})
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
	return map[string]any{
		"partition":           header.Partition(),
		"is_native_language":  header.IsNativeLanguage(),
		"language_id":         header.LanguageID(),
		"language_version_id": header.LanguageVersionID(),
		"language_type_id":    header.LanguageTypeID(),
		"code_type_id":        header.CodeTypeID(),
		"code_id":             header.CodeID(),
		"data":                base64.StdEncoding.EncodeToString(data),
	}, nil
}

// blobTableString formats a blob object as an aligned inspect table with all CBOR fields.
// Columns: PARTITION | IS-NATIVE | LANG-ID | LANG-VER-ID | LANG-TYPE-ID | CODE-TYPE-ID | CODE-ID | DATA (base64)
func (m *Manager) blobTableString(objInfo objects.ObjectInfo) (string, error) {
	header := objInfo.Header()
	if header == nil {
		return "", errors.New("cli: blob header is nil")
	}

	data, _ := objInfo.Instance().([]byte)
	headers := []string{"PARTITION", "IS-NATIVE", "LANG-ID", "LANG-VER-ID", "LANG-TYPE-ID", "CODE-TYPE-ID", "CODE-ID", "DATA"}
	dataRow := []string{
		header.Partition(),
		strconv.FormatBool(header.IsNativeLanguage()),
		fmt.Sprintf("%d", header.LanguageID()),
		fmt.Sprintf("%d", header.LanguageVersionID()),
		fmt.Sprintf("%d", header.LanguageTypeID()),
		fmt.Sprintf("%d", header.CodeTypeID()),
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
		common.NameText,
		common.NormalText,
	}

	var sb strings.Builder
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
