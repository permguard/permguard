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
			for _, objInfo := range filteredObjectInfos {
				objID := objInfo.GetOID()
				objType := objInfo.GetType()
				objHeader := objInfo.GetHeader()
				if objHeader != nil {
					codeID := objHeader.GetCodeID()
					out(nil, "", fmt.Sprintf("	- %s %s %s", aziclicommon.IDText(objID), aziclicommon.KeywordText(objType), aziclicommon.NameText(codeID)), nil, true)
				} else {
					out(nil, "", fmt.Sprintf("	- %s %s", aziclicommon.IDText(objID), aziclicommon.KeywordText(objType)), nil, true)
				}
				switch objInfo.GetType() {
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
		}
	} else if m.ctx.IsJSONOutput() {
		objMaps := []map[string]any{}
		for _, objInfo := range filteredObjectInfos {
			objMap := map[string]any{}
			objMap["oid"] = objInfo.GetOID()
			objMap["otype"] = objInfo.GetType()
			objMap["osize"] = len(objInfo.GetObject().GetContent())
			objHeader := objInfo.GetHeader()
			if objHeader != nil {
				codeID := objHeader.GetCodeID()
				objMap["oname"] = codeID
			}
			objMaps = append(objMaps, objMap)
		}
		output = out(output, "objects", objMaps, nil, true)
	}

	return output, nil
}

// execPrintObjectContent prints the object content.
func (m *WorkspaceManager) execPrintObjectContent(oid string, objInfo azlangobjs.ObjectInfo, out aziclicommon.PrinterOutFunc) error {
	switch instance := objInfo.GetInstance().(type) {
	case *azlangobjs.Commit:
		content, err := m.getCommitString(oid, instance)
		if err != nil {
			return err
		}
		out(nil, "", content, nil, true)
	case *azlangobjs.Tree:
		content, err := m.getTreeString(oid, instance)
		if err != nil {
			return err
		}
		out(nil, "", content, nil, true)
	case []byte:
		content, _, err := m.getBlobString(instance)
		if err != nil {
			return err
		}
		out(nil, "", string(content), nil, true)
	default:
		out(nil, "", string(objInfo.GetObject().GetContent()), nil, true)
	}
	return nil
}

// execMapObjectContent returns the object content as a map.
func (m *WorkspaceManager) execMapObjectContent(oid string, objInfo azlangobjs.ObjectInfo, outMap map[string]any) (error) {
	var contentMap map[string]any
	var err error
	switch instance := objInfo.GetInstance().(type) {
	case *azlangobjs.Commit:
		contentMap, err = m.getCommitMap(oid, instance)
		if err != nil {
			return err
		}
	case *azlangobjs.Tree:
		contentMap, err = m.getTreeMap(oid, instance)
		if err != nil {
			return err
		}
	case []byte:
		contentMap, err = m.getBlobMap(instance)
		if err != nil {
			return err
		}
	default:
		contentMap = map[string]any{}
		contentMap["raw_content"] = base64.StdEncoding.EncodeToString(objInfo.GetObject().GetContent())
	}
	for key, value := range contentMap {
		outMap[key] = value
	}
	return nil
}

// ExecObjectsCat cat the object.
func (m *WorkspaceManager) ExecObjectsCat(includeStorage, includeCode, showFrontendLanguage, showRaw, showContent bool, oid string, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
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

	obj := objectInfo.GetObject()
	objHeader := objectInfo.GetHeader()
	if m.ctx.IsTerminalOutput() {
		if showContent {
			if !showRaw {
				m.execPrintObjectContent(oid, *objectInfo, out)
			} else {
				out(nil, "", string(obj.GetContent()), nil, true)
			}
		} else {
			anyOutput := false
			out(nil, "", fmt.Sprintf("Your workspace object %s:\n", aziclicommon.IDText(objectInfo.GetOID())), nil, true)
			if anyOutput {
				out(nil, "", "\n", nil, false)
			}
			if !showRaw {
				m.execPrintObjectContent(oid, *objectInfo, out)
			} else {
				out(nil, "", string(obj.GetContent()), nil, true)
			}
			out(nil, "", "\n", nil, false)
			var sb strings.Builder
			sb.WriteString("type " + aziclicommon.KeywordText(objectInfo.GetType()))
			sb.WriteString(", size " + aziclicommon.NumberText(len(obj.GetContent())))
			if objHeader != nil {
				codeID := objHeader.GetCodeID()
				sb.WriteString(", oname " + aziclicommon.NameText(codeID))
			}
			out(nil, "", sb.String(), nil, true)
		}
	} else if m.ctx.IsJSONOutput() {
		objMap := map[string]any{}
		if !showRaw {
			err := m.execMapObjectContent(oid, *objectInfo, objMap)
			if err != nil {
				return failedOpErr(nil, err)
			}
		} else {
			objMap["raw_content"] = base64.StdEncoding.EncodeToString(obj.GetContent())
		}
		if !showContent {
			objMap["oid"] = objectInfo.GetOID()
			objMap["otype"] = objectInfo.GetType()
			objMap["osize"] = len(obj.GetContent())
			if objHeader != nil {
				codeID := objHeader.GetCodeID()
				objMap["oname"] = codeID
			}
		}
		objMaps := []map[string]any{}
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
	headCommit := headCtx.GetRemoteCommitID()
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
				commitStr, err := m.getCommitString(commitInfo.GetCommitOID(), commit)
				if err != nil {
					return failedOpErr(nil, err)
				}
				out(nil, "", commitStr, nil, true)
			}
			out(nil, "", "\n", nil, false)
			out(nil, "", "total " + aziclicommon.NumberText(len(commitInfos)), nil, true)
		}
	} else if m.ctx.IsJSONOutput() {
		objMaps := []map[string]any{}
		for _, commitInfo := range commitInfos {
			commit := commitInfo.GetCommit()
			objMap, err := m.getCommitMap(commitInfo.GetCommitOID(), commit)
			if err != nil {
				return failedOpErr(nil, err)
			}
			objMaps = append(objMaps, objMap)
		}
		output = out(output, "commits", objMaps, nil, true)
	}
	return output, nil
}
