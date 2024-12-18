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
	"fmt"
	"strings"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
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
func (m *WorkspaceManager) getCommitString(oid string, commit *azlangobjs.Commit) string {
	tree := commit.GetTree()
	metadata := commit.GetMetaData()
	committerTimestamp := metadata.GetCommitterTimestamp()
	authorTimestamp := metadata.GetAuthorTimestamp()

	output := fmt.Sprintf(
		"Commit %s:\n"+
			"  - Tree: %s\n"+
			"  - Committer Timestamp: %s\n"+
			"  - Author Timestamp: %s",
		aziclicommon.IDText(oid),
		aziclicommon.IDText(tree),
		aziclicommon.DateText(committerTimestamp),
		aziclicommon.DateText(authorTimestamp),
	)
	return output
}

// getTreeString gets the tree string.
func (m *WorkspaceManager) getTreeString(oid string, tree *azlangobjs.Tree) string {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("Tree %s:", aziclicommon.IDText(oid)))

	entries := tree.GetEntries()
	for _, entry := range entries {
		language := entry.GetLanguage()
		languageType := entry.GetLanguageType()
		languageVersion := entry.GetLanguageVersion()
		oid := entry.GetOID()
		oname := entry.GetOName()
		entryType := entry.GetType()
		output.WriteString(fmt.Sprintf("\n  - %s %s %s %s %s %s", aziclicommon.IDText(oid), aziclicommon.KeywordText(entryType), aziclicommon.NameText(oname), language, languageVersion, languageType))
	}

	return output.String()
}
