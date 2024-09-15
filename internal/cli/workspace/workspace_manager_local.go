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
	azicliwkscosp "github.com/permguard/permguard/internal/cli/workspace/cosp"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlang "github.com/permguard/permguard/pkg/core/languages"
)

// cleanupLocalArea cleans up the local area.
func (m *WorkspaceManager) cleanupLocalArea() (bool, error) {
	return m.cospMgr.CleanCodeArea()
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
		codeFiles[i] = azicliwkscosp.CodeFile{Type: azicliwkscosp.CodeFileTypePermCode, Path: file}
	}
	schemaFiles := []string{schemaYMLFile, schemaYAMLFile}
	existingSchemaFiles := []string{}
	for _, schemaFile := range schemaFiles {
		if exists, _ := m.persMgr.CheckFileIfExists(azicliwkspers.WorkspaceDir, schemaFile); exists {
			schemaFileName := m.persMgr.GetRelativeDir(azicliwkspers.WorkspaceDir, schemaFile)
			existingSchemaFiles = append(existingSchemaFiles, schemaFileName)
			codeFiles = append(codeFiles, azicliwkscosp.CodeFile{Type: azicliwkscosp.CodeFilePermSchema, Path: schemaFileName})
		}
	}
	schemaFileSet := make(map[string]struct{})
	for _, schemaFile := range existingSchemaFiles {
		schemaFileSet[schemaFile] = struct{}{}
	}
	ignoredCodeFiles := []azicliwkscosp.CodeFile{}
	for _, file := range ignoredFiles {
		if _, exists := schemaFileSet[file]; !exists {
			ignoredCodeFiles = append(ignoredCodeFiles, azicliwkscosp.CodeFile{Path: file})
		}
	}
	return codeFiles, ignoredCodeFiles, nil
}

// blobifyPermSchemaFile blobify a permguard schema file.
func (m *WorkspaceManager) blobifyPermSchemaFile(schemaFileCount int, path string, wkdir string, mode uint32, blbCodeFiles []azicliwkscosp.CodeFile, absLang azlang.LanguageAbastraction, data []byte, file azicliwkscosp.CodeFile) []azicliwkscosp.CodeFile {
	if schemaFileCount > 1 {
		codeFile := azicliwkscosp.CodeFile{
			Path:         strings.TrimPrefix(path, wkdir),
			Section:      0,
			Mode:         mode,
			HasErrors:    true,
			ErrorMessage: "permcode: only one schema file is permitted in the workspace. please ensure that there are no duplicate schema files",
		}
		blbCodeFiles = append(blbCodeFiles, codeFile)
	} else {
		multiSecObj, err := absLang.CreateSchemaSectionsObject(path, data)
		if err != nil {
			codeFile := &azicliwkscosp.CodeFile{
				Type:         file.Type,
				Path:         strings.TrimPrefix(path, wkdir),
				Section:      0,
				Mode:         mode,
				HasErrors:    true,
				ErrorMessage: err.Error(),
			}
			blbCodeFiles = append(blbCodeFiles, *codeFile)
			return blbCodeFiles
		}
		secObj := multiSecObj.GetSectionObjects()[0]
		codeFile := &azicliwkscosp.CodeFile{
			Type:      file.Type,
			Path:      strings.TrimPrefix(path, wkdir),
			Section:   secObj.GetNumberOfSection(),
			Mode:      mode,
			HasErrors: secObj.GetError() != nil,
			OType:     secObj.GetObjectType(),
			OName:     secObj.GetObjectName(),
		}
		if codeFile.HasErrors {
			codeFile.ErrorMessage = azerrors.GetSystemErrorMessage(secObj.GetError())
		} else {
			obj := secObj.GetObject()
			codeFile.OID = obj.GetOID()
			m.cospMgr.SaveObject(obj.GetOID(), obj.GetContent(), true)
		}
		blbCodeFiles = append(blbCodeFiles, *codeFile)
	}
	return blbCodeFiles
}

// blobifyPermSchemaFile blobify a permguard code file.
func (m *WorkspaceManager) blobifyPermCodeFile(absLang azlang.LanguageAbastraction, path string, data []byte, file azicliwkscosp.CodeFile, wkdir string, mode uint32, blbCodeFiles []azicliwkscosp.CodeFile) []azicliwkscosp.CodeFile {
	multiSecObj, err := absLang.CreateMultiSectionsObjects(path, data)
	if err != nil {
		codeFile := &azicliwkscosp.CodeFile{
			Type:         file.Type,
			Path:         strings.TrimPrefix(path, wkdir),
			Section:      -1,
			Mode:         mode,
			HasErrors:    true,
			ErrorMessage: err.Error(),
		}
		blbCodeFiles = append(blbCodeFiles, *codeFile)
		return blbCodeFiles
	}
	secObjs := multiSecObj.GetSectionObjects()
	for _, secObj := range secObjs {
		codeFile := &azicliwkscosp.CodeFile{
			Type:      file.Type,
			Path:      strings.TrimPrefix(path, wkdir),
			Section:   secObj.GetNumberOfSection(),
			Mode:      mode,
			HasErrors: secObj.GetError() != nil,
			OType:     secObj.GetObjectType(),
			OName:     secObj.GetObjectName(),
		}
		if codeFile.HasErrors {
			codeFile.ErrorMessage = azerrors.GetSystemErrorMessage(secObj.GetError())
		} else {
			obj := secObj.GetObject()
			codeFile.OID = obj.GetOID()
			m.cospMgr.SaveObject(obj.GetOID(), obj.GetContent(), true)
		}
		blbCodeFiles = append(blbCodeFiles, *codeFile)
	}
	return blbCodeFiles
}

// blobifyLocal scans source files and creates a blob for each object.
func (m *WorkspaceManager) blobifyLocal(codeFiles []azicliwkscosp.CodeFile, absLang azlang.LanguageAbastraction) (string, []azicliwkscosp.CodeFile, error) {
	blbCodeFiles := []azicliwkscosp.CodeFile{}
	schemaFileCount := 0
	for _, file := range codeFiles {
		wkdir := m.ctx.GetWorkDir()
		path := file.Path
		data, mode, err := m.persMgr.ReadFile(azicliwkspers.WorkDir, path, false)
		if err != nil {
			return "", nil, err
		}
		if file.Type == azicliwkscosp.CodeFileTypePermCode {
			blbCodeFiles = m.blobifyPermCodeFile(absLang, path, data, file, wkdir, mode, blbCodeFiles)
		} else if file.Type == azicliwkscosp.CodeFilePermSchema {
			schemaFileCount++
			blbCodeFiles = m.blobifyPermSchemaFile(schemaFileCount, path, wkdir, mode, blbCodeFiles, absLang, data, file)
		} else {
			return "", nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: file type is not supported")
		}
	}
	if schemaFileCount == 0 {
		codeFile := azicliwkscosp.CodeFile{
			Path:         m.persMgr.GetRelativeDir(azicliwkspers.WorkspaceDir, schemaYAMLFile),
			Section:      0,
			Mode:         0,
			HasErrors:    true,
			ErrorMessage: "permcode: the schema file 'schema.yml' is missing. please ensure there are no duplicate schema files and that the required schema file is present.",
		}
		blbCodeFiles = append(blbCodeFiles, codeFile)
	}
	if err := m.cospMgr.SaveCodeMap(blbCodeFiles); err != nil {
		return "", blbCodeFiles, err
	}
	codeObsState, err := m.cospMgr.ConvertCodeFilesToCodeObjects(blbCodeFiles)
	if err != nil {
		return "", blbCodeFiles, err
	}
	if err := m.cospMgr.SaveCodeState(codeObsState); err != nil {
		return "", blbCodeFiles, err
	}
	tree := azlangobjs.NewTree()
	hasErrors := false
	for _, file := range blbCodeFiles {
		if file.HasErrors {
			hasErrors = true
		}
		if err := tree.AddEntry(azlangobjs.NewTreeEntry(file.OType, file.OID, file.OName)); err != nil {
			return "", blbCodeFiles, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: tree item cannot be added to the tree because of errors in the code files")
		}
	}
	if hasErrors {
		return "", blbCodeFiles, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: blobification process failed because of errors in the code files")
	}
	treeObj, err := absLang.CreateTreeObject(tree)
	if err != nil {
		return "", blbCodeFiles, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: tree object cannot be created")
	}
	m.cospMgr.SaveObject(treeObj.GetOID(), treeObj.GetContent(), true)
	treeID := treeObj.GetOID()
	if err := m.cospMgr.SaveCodeAreaConfig(treeID, absLang.GetLanguageName()); err != nil {
		return treeID, blbCodeFiles, err
	}
	return treeID, blbCodeFiles, nil
}

// retrieveCodeMap retrieves the code map.
func (m *WorkspaceManager) retrieveCodeMap() ([]azicliwkscosp.CodeFile, []azicliwkscosp.CodeFile, error) {
	codeFiles, err := m.cospMgr.ReadCodeMap()
	if err != nil {
		return nil, nil, err
	}
	validFiles := []azicliwkscosp.CodeFile{}
	invalidFiles := []azicliwkscosp.CodeFile{}
	for _, codeFile := range codeFiles {
		if codeFile.HasErrors {
			invalidFiles = append(invalidFiles, codeFile)
		}
		if !codeFile.HasErrors {
			validFiles = append(validFiles, codeFile)
		}
	}
	return validFiles, invalidFiles, nil
}
