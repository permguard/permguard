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
	"fmt"
	"strings"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// GetObjects gets the objects.
func (m *WorkspaceManager) getObjectsInfos(includeStorage, includeCode, filterCommits, filterTrees, filterBlob bool) ([]azlangobjs.ObjectInfo, error) {
	filteredObjects := []azlangobjs.ObjectInfo{}
	objects, err := m.cospMgr.GetObjects(includeStorage, includeCode)
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return filteredObjects, nil
	}

	objMgr, err := azlangobjs.NewObjectManager()
	if err != nil {
		return nil, err
	}

	for _, object := range objects {
		objInfo, err := objMgr.GetObjectInfo(&object)
		if err != nil {
			return nil, err
		}
		if objInfo.GetType() == azlangobjs.ObjectTypeCommit && !filterCommits {
			continue
		} else if objInfo.GetType() == azlangobjs.ObjectTypeTree && !filterTrees {
			continue
		} else if objInfo.GetType() == azlangobjs.ObjectTypeBlob && !filterBlob {
			continue
		}
		filteredObjects = append(filteredObjects, *objInfo)
	}
	return filteredObjects, nil
}

// getHistory gets the commit history.
func (m *WorkspaceManager) getHistory(commit string) ([]azicliwkscommon.CommitInfo, error) {
	commitHistory, err := m.cospMgr.GetHistory(commit)
	if err != nil {
		return nil, err
	}
	return commitHistory, nil
}

// getCommitString gets the commit string.
func (m *WorkspaceManager) getCommitString(oid string, commit *azlangobjs.Commit) (string, error) {
	if commit == nil {
		return "", azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliGeneric, "commit is nil")
	}

	tree := commit.GetTree()
	metadata := commit.GetMetaData()
	committerTimestamp := metadata.GetCommitterTimestamp()
	authorTimestamp := metadata.GetAuthorTimestamp()

	output := fmt.Sprintf(
		"%s %s:\n"+
			"  - %s: %s\n"+
			"  - Committer date: %s\n"+
			"  - Author date: %s",
		aziclicommon.KeywordText("commit"),
		aziclicommon.IDText(oid),
		aziclicommon.KeywordText("tree"),
		aziclicommon.IDText(tree),
		aziclicommon.DateText(committerTimestamp),
		aziclicommon.DateText(authorTimestamp),
	)
	return output, nil
}

// getCommitMap gets the commit map.
func (m *WorkspaceManager) getCommitMap(oid string, commit *azlangobjs.Commit) (map[string]any, error) {
	if commit == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliGeneric, "commit is nil")
	}

	output := make(map[string]any)
	output["oid"] = oid
	output["parent"] = commit.GetParent()
	output["tree"] = commit.GetTree()
	output["message"] = commit.GetMessage()

	metdata := commit.GetMetaData()
	output["author"] = metdata.GetAuthor()
	output["author_timestamp"] = metdata.GetAuthorTimestamp()
	output["committer"] = metdata.GetCommitter()
	output["committer_timestamp"] = metdata.GetCommitterTimestamp()
	return output, nil
}

// getTreeString gets the tree string.
func (m *WorkspaceManager) getTreeString(oid string, tree *azlangobjs.Tree) (string, error) {
	if tree == nil {
		return "", azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliGeneric, "tree is nil")
	}

	var output strings.Builder

	output.WriteString(fmt.Sprintf("%s %s:", aziclicommon.KeywordText("tree"), aziclicommon.IDText(oid)))

	entries := tree.GetEntries()
	for _, entry := range entries {
		language := entry.GetLanguage()
		languageType := entry.GetLanguageType()
		languageVersion := entry.GetLanguageVersion()
		oid := entry.GetOID()
		oname := entry.GetOName()
		entryType := entry.GetType()
		output.WriteString(fmt.Sprintf("\n  - %s %s %s %s %s %s", aziclicommon.IDText(oid), aziclicommon.KeywordText(entryType), aziclicommon.NameText(oname), aziclicommon.LanguageText(language), aziclicommon.LanguageText(languageVersion), aziclicommon.LanguageKeywordText(languageType)))
	}

	return output.String(), nil
}

// getTreeMap gets the tree map.
func (m *WorkspaceManager) getTreeMap(oid string, tree *azlangobjs.Tree) (map[string]any, error) {
	if tree == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliGeneric, "tree is nil")
	}

	output := make(map[string]any)
	output["oid"] = oid

	entries := tree.GetEntries()
	entriesList := make([]map[string]any, len(entries))

	for i, entry := range entries {
		entryMap := make(map[string]any)
		entryMap["oid"] = entry.GetOID()
		entryMap["oname"] = entry.GetOName()
		entryMap["type"] = entry.GetType()
		entryMap["language"] = entry.GetLanguage()
		entryMap["language_type"] = entry.GetLanguageType()
		entryMap["language_version"] = entry.GetLanguageVersion()
		entriesList[i] = entryMap
	}

	output["entries"] = entriesList
	return output, nil
}

// getBlobString gets the blob string.
func (m *WorkspaceManager) getBlobString(blob any) ([]byte, bool, error) {
	if blob == nil {
		return nil, false, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliGeneric, "tree is nil")
	}
	content, hasContent := blob.([]byte)
	if !hasContent {
		return nil, false, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliGeneric, "blob content is not a byte array")
	}
	return content, true, nil
}

// getBlobString gets the blob map.
func (m *WorkspaceManager) getBlobMap(blob any) (map[string]any, error) {
	if blob == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliGeneric, "tree is nil")
	}
	content, hasContent := blob.([]byte)
	if !hasContent {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliGeneric, "blob content is not a byte array")
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
