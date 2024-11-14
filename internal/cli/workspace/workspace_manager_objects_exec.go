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

// ExecObjects list the objects.
func (m *WorkspaceManager) ExecObjects(includeStorage, includeCode, filterCommits, filterTrees, filterBlob bool, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to access objects in the current workspace.", nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	filteredObjectInfos, err := m.getObjectsInfos(includeStorage, includeCode, filterCommits, filterTrees, filterBlob)
	if err != nil {
		return failedOpErr(nil, err)
	}

	if m.ctx.IsTerminalOutput() {
		if len(filteredObjectInfos) == 0 {
			out(nil, "", "No objects found in the current workspace.", nil, true)
			return output, nil
		} else {
			out(nil, "", "Your workspace objects:\n", nil, true)
			total, commits, trees, blobs := 0, 0, 0, 0
			for _, objectInfo := range filteredObjectInfos {
				out(nil, "", fmt.Sprintf("	- %s %s", aziclicommon.IDText(objectInfo.GetOID()), aziclicommon.KeywordText(objectInfo.GetType())), nil, true)
				switch objectInfo.GetType() {
				case azlangobjs.ObjectTypeCommit:
					commits = commits + 1
					if filterCommits {
						total += 1
					}
				case azlangobjs.ObjectTypeTree:
					trees = trees + 1
					if filterTrees {
						total += 1
					}
				case azlangobjs.ObjectTypeBlob:
					blobs = blobs + 1
					if filterBlob {
						total += 1
					}
				}
			}
			out(nil, "", "\n", nil, false)
			var sb strings.Builder
			if filterCommits || filterTrees || filterBlob {
				sb.WriteString("total " + aziclicommon.NumberText(total))

				if filterCommits {
					sb.WriteString(", commit " + aziclicommon.NumberText(commits))
				}
				if filterTrees {
					sb.WriteString(", tree " + aziclicommon.NumberText(trees))
				}
				if filterBlob {
					sb.WriteString(", blob " + aziclicommon.NumberText(blobs))
				}
				out(nil, "", sb.String(), nil, true)
			}
			out(nil, "", "", nil, true)
		}
	} else if m.ctx.IsJSONOutput() {
		objMaps := []map[string]any{}
		for _, object := range filteredObjectInfos {
			objMap := map[string]any{}
			objMap["type"] = object.GetType()
			objMap["size"] = len(object.GetObject().GetContent())
			objMaps = append(objMaps, objMap)
		}
		output = out(output, "objects", objMaps, nil, true)
	}

	return output, nil
}

// ExecObjectsCat cat the object.
func (m *WorkspaceManager) ExecObjectsCat(includeStorage, includeCode, showType, showSize, showContent bool, oid string, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to access objects in the current workspace.", nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	filteredObjectsInfos, err := m.getObjectsInfos(includeStorage, includeCode, true, true, true)
	if err != nil {
		return failedOpErr(nil, err)
	}
	var objectInfo *azlangobjs.ObjectInfo
	for _, objInfo := range filteredObjectsInfos {
		if objInfo.GetOID() == oid {
			objectInfo = &objInfo
			break
		}
	}
	if objectInfo == nil {
		return failedOpErr(nil, fmt.Errorf("object not found"))
	}

	if m.ctx.IsTerminalOutput() {
		anyOutput := false
		out(nil, "", fmt.Sprintf("Your workspace object %s:\n", aziclicommon.IDText(objectInfo.GetOID())), nil, true)
		if showType {
			out(nil, "", fmt.Sprintf("	- Type %s", aziclicommon.KeywordText(objectInfo.GetType())), nil, true)
			anyOutput = true
		}
		if showSize {
			out(nil, "", fmt.Sprintf("	- Size %s", aziclicommon.NumberText(len(objectInfo.GetObject().GetContent()))), nil, true)
			anyOutput = true
		}
		if showContent {
			if anyOutput {
				out(nil, "", "\n", nil, false)
			}
			out(nil, "", string(objectInfo.GetObject().GetContent()), nil, true)
		}
		out(nil, "", "\n", nil, false)
	} else if m.ctx.IsJSONOutput() {
		objMaps := []map[string]any{}
		objMap := map[string]any{}
		if showType {
			objMap["type"] = objectInfo.GetType()
		}
		if showSize {
			objMap["size"] = len(objectInfo.GetObject().GetContent())
		}
		if showContent {
			objMap["content"] = string(objectInfo.GetObject().GetContent())
		}
		objMaps = append(objMaps, objMap)
		output = out(output, "objects", objMaps, nil, true)
	}
	return output, nil
}

// ExecHistory show the history.
func (m *WorkspaceManager) ExecHistory(out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to access history in the current workspace.", nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	// Read current head settings
	headCtx, err := m.getCurrentHeadContext()
	if err != nil {
		return failedOpErr(nil, err)
	}

	// Get history of the current workspace
	commitInfos := []azicliwkscommon.CommitInfo{}
	headCommit := headCtx.GetCommit()
	if headCommit != azlangobjs.ZeroOID {
		commitInfos, err = m.getHistory(headCommit)
		if err != nil {
			return failedOpErr(nil, err)
		}
	}

	if m.ctx.IsTerminalOutput() {
		if len(commitInfos) == 0 {
			out(nil, "", "No history data is available in the current workspace.", nil, true)
			return output, nil
		} else {
			out(nil, "", fmt.Sprintf("Your workspace history %s:\n", aziclicommon.KeywordText(headCtx.GetRepoURI())), nil, true)
			for _, commitInfo := range commitInfos {
				commit := commitInfo.GetCommit()
				tree := commit.GetTree()
				metadata := commit.GetMetaData()
				committerTimestamp := metadata.GetCommitterTimestamp()
				authorTimestamp := metadata.GetAuthorTimestamp()

				output := fmt.Sprintf(
					"Commit %s:\n"+
						"  - Tree: %s\n"+
						"  - Committer Timestamp: %s\n"+
						"  - Author Timestamp: %s\n",
					aziclicommon.IDText(commitInfo.GetCommitOID()),
					aziclicommon.IDText(tree),
					aziclicommon.DateText(committerTimestamp),
					aziclicommon.DateText(authorTimestamp),
				)

				out(nil, "", output, nil, true)
			}
		}
	} else if m.ctx.IsJSONOutput() {
		objMaps := []map[string]any{}
		for _, commitInfo := range commitInfos {
			commit := commitInfo.GetCommit()
			objMap := map[string]any{}
			objMap["commit_id"] = commitInfo.GetCommitOID()
			objMap["parent"] = commit.GetParent()
			objMap["tree"] = commit.GetTree()
			metadata := commit.GetMetaData()
			objMap["author"] = metadata.GetAuthor()
			objMap["author_timestamp"] = metadata.GetAuthorTimestamp()
			objMap["committer"] = metadata.GetCommitter()
			objMap["committer_timestamp"] = metadata.GetCommitterTimestamp()
			objMaps = append(objMaps, objMap)
		}
		output = out(output, "commits", objMaps, nil, true)
	}
	return output, nil
}
