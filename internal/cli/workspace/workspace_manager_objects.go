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
	"strings"

	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"

	"github.com/permguard/permguard/internal/cli/common"
	wkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
)

// objectsInfos retrieves and filters object metadata based on object type.
func (m *WorkspaceManager) objectsInfos(includeStorage, includeCode, filterCommits, filterTrees, filterBlob bool) ([]objects.ObjectInfo, error) {
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
func (m *WorkspaceManager) history(commit string) ([]wkscommon.CommitInfo, error) {
	commitHistory, err := m.cospMgr.History(commit)
	if err != nil {
		return nil, err
	}
	return commitHistory, nil
}

// commitString gets the commit string.
func (m *WorkspaceManager) commitString(oid string, commit *objects.Commit) (string, error) {
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
func (m *WorkspaceManager) commitMap(oid string, commit *objects.Commit) (map[string]any, error) {
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
func (m *WorkspaceManager) treeString(oid string, tree *objects.Tree) (string, error) {
	if tree == nil {
		return "", errors.New("cli: tree is nil")
	}

	var output strings.Builder

	output.WriteString(fmt.Sprintf("%s %s:", common.KeywordText("tree"), common.IDText(oid)))

	entries := tree.Entries()
	for _, entry := range entries {
		partition := entry.Partition()
		language := entry.Language()
		languageType := entry.LanguageType()
		languageVersion := entry.LanguageVersion()
		oid := entry.OID()
		oname := entry.OName()
		entryType := entry.Type()
		output.WriteString(fmt.Sprintf("\n  - %s %s %s %s %s %s %s", common.IDText(oid), common.KeywordText(entryType), common.NameText(partition),
			common.NameText(oname), common.LanguageText(language), common.LanguageText(languageVersion), common.LanguageKeywordText(languageType)))
	}

	return output.String(), nil
}

// treeMap gets the tree map.
func (m *WorkspaceManager) treeMap(oid string, tree *objects.Tree) (map[string]any, error) {
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
func (m *WorkspaceManager) blobString(blob any) ([]byte, bool, error) {
	if blob == nil {
		return nil, false, errors.New("cli: tree is nil")
	}
	content, hasContent := blob.([]byte)
	if !hasContent {
		return nil, false, errors.New("cli: blob content is not a byte array")
	}
	return content, true, nil
}

// getBlobString gets the blob map.
func (m *WorkspaceManager) blobMap(blob any) (map[string]any, error) {
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
