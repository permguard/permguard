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
	"errors"
	"fmt"
	"strings"

	"github.com/permguard/permguard/internal/cli/common"
	wkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/pkg/authz/languages"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// ExecObjects list the objects.
func (m *WorkspaceManager) ExecObjects(includeStorage, includeCode, filterCommits, filterTrees, filterBlob bool, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to access objects in the current workspace.", nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return fail(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return fail(nil, err)
	}
	defer fileLock.Unlock()

	filteredObjectInfos, err := m.getObjectsInfos(includeStorage, includeCode, filterCommits, filterTrees, filterBlob)
	if err != nil {
		return fail(nil, err)
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
					out(nil, "", fmt.Sprintf("	- %s %s %s", common.IDText(objID), common.KeywordText(objType), common.NameText(codeID)), nil, true)
				} else {
					out(nil, "", fmt.Sprintf("	- %s %s", common.IDText(objID), common.KeywordText(objType)), nil, true)
				}
				switch objInfo.GetType() {
				case objects.ObjectTypeCommit:
					commits = commits + 1
					if filterCommits {
						total += 1
					}
				case objects.ObjectTypeTree:
					trees = trees + 1
					if filterTrees {
						total += 1
					}
				case objects.ObjectTypeBlob:
					blobs = blobs + 1
					if filterBlob {
						total += 1
					}
				}
			}
			out(nil, "", "\n", nil, false)
			var sb strings.Builder
			if filterCommits || filterTrees || filterBlob {
				sb.WriteString("total " + common.NumberText(total))

				if filterCommits {
					sb.WriteString(", commit " + common.NumberText(commits))
				}
				if filterTrees {
					sb.WriteString(", tree " + common.NumberText(trees))
				}
				if filterBlob {
					sb.WriteString(", blob " + common.NumberText(blobs))
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

// execPrintObjectContent prints the object content in human-readable form,
// optionally converting blob data to a frontend-friendly format.
func (m *WorkspaceManager) execPrintObjectContent(langPvd *ManifestLanguageProvider, oid string, objInfo objects.ObjectInfo, showFrontendLanguage bool, out common.PrinterOutFunc) error {
	switch instance := objInfo.GetInstance().(type) {
	case *objects.Commit:
		content, err := m.getCommitString(oid, instance)
		if err != nil {
			return err
		}
		out(nil, "", content, nil, true)

	case *objects.Tree:
		content, err := m.getTreeString(oid, instance)
		if err != nil {
			return err
		}
		out(nil, "", content, nil, true)

	case []byte:
		instanceBytes := instance

		if showFrontendLanguage {
			header := objInfo.GetHeader()
			if header == nil {
				return errors.New("cli: object header s nil")
			}

			absLang, err := langPvd.GetAbstractLanguage(header.GetPartition())
			if err != nil {
				return err
			}

			instanceBytes, err = absLang.ConvertBytesToFrontendLanguage(
				nil,
				header.GetLanguageID(),
				header.GetLanguageVersionID(),
				header.GetLanguageTypeID(),
				instance,
			)
			if err != nil {
				return err
			}
		}

		content, _, err := m.getBlobString(instanceBytes)
		if err != nil {
			return err
		}
		out(nil, "", string(content), nil, true)

	default:
		out(nil, "", string(objInfo.GetObject().GetContent()), nil, true)
	}

	return nil
}

// execMapObjectContent builds a key-value representation of the object content,
// optionally transforming blob data into a structured frontend format.
func (m *WorkspaceManager) execMapObjectContent(langPvd *ManifestLanguageProvider, oid string, objInfo objects.ObjectInfo, showFrontendLanguage bool, outMap map[string]any) error {
	var contentMap map[string]any
	var err error

	switch instance := objInfo.GetInstance().(type) {
	case *objects.Commit:
		contentMap, err = m.getCommitMap(oid, instance)
		if err != nil {
			return err
		}

	case *objects.Tree:
		contentMap, err = m.getTreeMap(oid, instance)
		if err != nil {
			return err
		}

	case []byte:
		instanceBytes := instance

		if showFrontendLanguage {
			header := objInfo.GetHeader()
			if header == nil {
				return errors.New("cli: object header s nil")
			}

			var absLang languages.LanguageAbastraction
			absLang, err = langPvd.GetAbstractLanguage(header.GetPartition())
			if err != nil {
				return err
			}

			instanceBytes, err = absLang.ConvertBytesToFrontendLanguage(
				nil,
				header.GetLanguageID(),
				header.GetLanguageVersionID(),
				header.GetLanguageTypeID(),
				instance,
			)
			if err != nil {
				return err
			}
		}

		contentMap, err = m.getBlobMap(instanceBytes)
		if err != nil {
			return err
		}

	default:
		// Fallback: raw base64-encoded content
		contentMap = map[string]any{
			"raw_content": base64.StdEncoding.EncodeToString(objInfo.GetObject().GetContent()),
		}
	}

	// Copy all keys to output map
	for k, v := range contentMap {
		outMap[k] = v
	}

	return nil
}

// ExecObjectsCat prints the content or metadata of a specific object identified by its OID.
func (m *WorkspaceManager) ExecObjectsCat(includeStorage, includeCode, showFrontendLanguage, showRaw, showContent bool, oid string, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to access objects in the current workspace.", nil, true)
		return output, err
	}

	output := m.ExecPrintContext(nil, out)

	// Validate workspace and acquire lock
	if !m.isWorkspaceDir() {
		return fail(nil, m.raiseWrongWorkspaceDirError(out))
	}
	fileLock, err := m.tryLock()
	if err != nil {
		return fail(nil, err)
	}
	defer fileLock.Unlock()

	// Search for the requested object
	objectInfos, err := m.getObjectsInfos(includeStorage, includeCode, true, true, true)
	if err != nil {
		return fail(nil, err)
	}
	var selected *objects.ObjectInfo
	for _, info := range objectInfos {
		if info.GetOID() == oid {
			selected = &info
			break
		}
	}
	if selected == nil {
		return fail(nil, fmt.Errorf("object not found"))
	}

	obj := selected.GetObject()
	header := selected.GetHeader()

	// Initialize language provider
	langPvd, err := m.buildManifestLanguageProvider()
	if err != nil {
		return fail(nil, err)
	}

	// Terminal output mode
	if m.ctx.IsTerminalOutput() {
		if showContent {
			if showRaw {
				out(nil, "", string(obj.GetContent()), nil, true)
			} else {
				if err := m.execPrintObjectContent(langPvd, oid, *selected, showFrontendLanguage, out); err != nil {
					return fail(nil, err)
				}
			}
		} else {
			out(nil, "", fmt.Sprintf("Your workspace object %s:\n", common.IDText(selected.GetOID())), nil, true)

			if showRaw {
				out(nil, "", string(obj.GetContent()), nil, true)
			} else {
				if err := m.execPrintObjectContent(langPvd, oid, *selected, showFrontendLanguage, out); err != nil {
					return fail(nil, err)
				}
			}

			out(nil, "", "\n", nil, false)

			var sb strings.Builder
			sb.WriteString("type " + common.KeywordText(selected.GetType()))
			sb.WriteString(", size " + common.NumberText(len(obj.GetContent())))
			if header != nil {
				sb.WriteString(", oname " + common.NameText(header.GetCodeID()))
			}
			out(nil, "", sb.String(), nil, true)
		}

		// JSON output mode
	} else if m.ctx.IsJSONOutput() {
		objMap := map[string]any{}

		if showRaw {
			objMap["raw_content"] = base64.StdEncoding.EncodeToString(obj.GetContent())
		} else {
			if err := m.execMapObjectContent(langPvd, oid, *selected, showFrontendLanguage, objMap); err != nil {
				return fail(nil, err)
			}
		}

		if !showContent {
			objMap["oid"] = selected.GetOID()
			objMap["otype"] = selected.GetType()
			objMap["osize"] = len(obj.GetContent())
			if header != nil {
				objMap["oname"] = header.GetCodeID()
			}
		}

		output = out(output, "objects", []map[string]any{objMap}, nil, true)
	}

	return output, nil
}

// ExecHistory shows the commit history of the current workspace.
func (m *WorkspaceManager) ExecHistory(out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to access history in the current workspace.", nil, true)
		return output, err
	}

	output := m.ExecPrintContext(nil, out)

	// Ensure we're in a valid workspace
	if !m.isWorkspaceDir() {
		return fail(nil, m.raiseWrongWorkspaceDirError(out))
	}

	// Acquire workspace lock
	fileLock, err := m.tryLock()
	if err != nil {
		return fail(nil, err)
	}
	defer fileLock.Unlock()

	// Read current head context
	headCtx, err := m.getCurrentHeadContext()
	if err != nil {
		return fail(nil, err)
	}

	// Load commit history from head
	var commitInfos []wkscommon.CommitInfo
	headCommit := headCtx.GetRemoteCommitID()
	if headCommit != objects.ZeroOID {
		commitInfos, err = m.getHistory(headCommit)
		if err != nil {
			return fail(nil, err)
		}
	}

	// Terminal output
	if m.ctx.IsTerminalOutput() {
		if len(commitInfos) == 0 {
			out(nil, "", "No history data is available in the current workspace.", nil, true)
			return output, nil
		}

		out(nil, "", fmt.Sprintf("Your workspace history %s:\n", common.KeywordText(headCtx.GetLedgerURI())), nil, true)

		for _, info := range commitInfos {
			commit := info.GetCommit()
			commitStr, err := m.getCommitString(info.GetCommitOID(), commit)
			if err != nil {
				return fail(nil, err)
			}
			out(nil, "", commitStr, nil, true)
		}

		out(nil, "", "\n", nil, false)
		out(nil, "", "total "+common.NumberText(len(commitInfos)), nil, true)

		// JSON output
	} else if m.ctx.IsJSONOutput() {
		var objMaps []map[string]any
		for _, info := range commitInfos {
			commit := info.GetCommit()
			objMap, err := m.getCommitMap(info.GetCommitOID(), commit)
			if err != nil {
				return fail(nil, err)
			}
			objMaps = append(objMaps, objMap)
		}
		output = out(output, "commits", objMaps, nil, true)
	}

	return output, nil
}
