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
	"strings"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azicliwkscosp "github.com/permguard/permguard/internal/cli/workspace/cosp"
	azlang "github.com/permguard/permguard/pkg/core/languages"
)

// cleanupStagingArea cleans up the staging area.
func (m *WorkspaceManager) cleanupStagingArea() (bool, error) {
	return m.cospMgr.CleanStagingArea()
}

// scanSourceCodeFiles scans the source code files.
func (m *WorkspaceManager) scanSourceCodeFiles(absLang azlang.LanguageAbastraction) ([]azicliwkscosp.CodeFile, []azicliwkscosp.CodeFile, error) {
	exts := absLang.GetFileExtensions()
	ignorePatterns := []string{hiddenIgnoreFile, schemaYAMLFile, schemaYMLFile, hiddenDir, gitDir, gitIgnoreFile}
	files, ignoredFiles, err := m.persMgr.ScanAndFilterFiles(azicliwkspers.WorkspaceDir, exts, ignorePatterns, hiddenIgnoreFile)
	if err != nil {
		return nil, nil, err
	}
	codeFiles := make([]azicliwkscosp.CodeFile, len(files))
	for i, file := range files {
		codeFiles[i] = azicliwkscosp.CodeFile{Path: file}
	}
	ignoredCodeFiles := make([]azicliwkscosp.CodeFile, len(ignoredFiles))
	for i, file := range ignoredFiles {
		ignoredCodeFiles[i] = azicliwkscosp.CodeFile{Path: file}
	}
	return codeFiles, ignoredCodeFiles, nil
}

// blobifyLocal scans source files and creates a blob for each object.
func (m *WorkspaceManager) blobifyLocal(codeFiles []azicliwkscosp.CodeFile, absLang azlang.LanguageAbastraction) (string, []azicliwkscosp.CodeFile, error) {
	blbCodeFiles := []azicliwkscosp.CodeFile{}
	for _, file := range codeFiles {
		wkdir := m.ctx.GetWorkDir()
		path := file.Path
		data, mode, err := m.persMgr.ReadFile(azicliwkspers.WorkDir, path, false)
		if err != nil {
			return "", nil, err
		}
		multiSecObj, err := absLang.CreateMultiSectionsObjects(path, data)
		if err != nil {
			continue
		}
		secObjs := multiSecObj.GetSectionObjects()
		for _, secObj := range secObjs {
			codeFile := &azicliwkscosp.CodeFile{
				Path:      strings.TrimPrefix(path, wkdir),
				Section:   secObj.GetNumberOfSection(),
				Mode:      mode,
				HasErrors: secObj.GetError() != nil,
				OType:     secObj.GetObjectType(),
				OName:     secObj.GetObjectName(),
			}
			if codeFile.HasErrors {
				codeFile.ErrorMessage = secObj.GetError().Error()
			} else {
				obj := secObj.GetObject()
				codeFile.OID = obj.GetOID()
				m.cospMgr.SaveObject(obj.GetOID(), obj.GetContent(), true)
			}
			blbCodeFiles = append(blbCodeFiles, *codeFile)
		}
	}
	tree := azlangobjs.NewTree()
	for _, file := range blbCodeFiles {
		tree.AddEntry(azlangobjs.NewTreeEntry(file.Mode, file.OType, file.OID, file.OName, file.Path))
	}
	treeObj, err := absLang.CreateTreeObject(tree)
	if err != nil {
		return "", nil, err
	}
	m.cospMgr.SaveObject(treeObj.GetOID(), treeObj.GetContent(), true)
	treeID := treeObj.GetOID()
	if err := m.cospMgr.SaveCodeStagingConfig(treeID, absLang.GetLanguageName()); err != nil {
		return "", nil, err
	}
	if err = m.cospMgr.SaveCodeMap(blbCodeFiles); err != nil {
		return "", nil, err
	}
	return treeID, blbCodeFiles, nil
}

// buildLocalState builds the local state.
func (m *WorkspaceManager) buildLocalState(treeID string, absLang azlang.LanguageAbastraction) error {
	obj, err := m.cospMgr.ReadObject(treeID, true)
	if err != nil {
		return err
	}
	tree, err := absLang.GetTreeeObject(obj)
	if err != nil {
		return err
	}
	print(tree)
	return nil
}
