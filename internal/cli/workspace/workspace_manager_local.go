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
	"path/filepath"
	"strings"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	aztypes "github.com/permguard/permguard-abs-language/pkg/permcode/types"
	azicliwkscosp "github.com/permguard/permguard/internal/cli/workspace/cosp"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlang "github.com/permguard/permguard/pkg/core/languages"
)

// groupCodeFiles groups the code files.
func groupCodeFiles(codeFiles []azicliwkscosp.CodeFile) map[string][]azicliwkscosp.CodeFile {
	grouped := map[string][]azicliwkscosp.CodeFile{}
	for _, codeFile := range codeFiles {
		if _, ok := grouped[codeFile.Path]; !ok {
			grouped[codeFile.Path] = []azicliwkscosp.CodeFile{}
		}
		grouped[codeFile.Path] = append(grouped[codeFile.Path], codeFile)
	}
	return grouped
}

// cleanupLocalArea cleans up the local area.
func (m *WorkspaceManager) cleanupLocalArea() (bool, error) {
	return m.cospMgr.CleanCodeSource()
}

// scanSourceCodeFiles scans the source code files.
func (m *WorkspaceManager) scanSourceCodeFiles(absLang azlang.LanguageAbastraction) ([]azicliwkscosp.CodeFile, []azicliwkscosp.CodeFile, error) {
	langSpec := absLang.GetLanguageSpecification()
	suppPolicyExts := langSpec.GetSupportedPolicyFileExtensions()
	ignorePatterns := []string{hiddenIgnoreFile, schemaYAMLFile, schemaYMLFile, hiddenDir, gitDir, gitIgnoreFile}
	files, ignoredFiles, err := m.persMgr.ScanAndFilterFiles(azicliwkspers.WorkspaceDir, "", suppPolicyExts, ignorePatterns, hiddenIgnoreFile)
	if err != nil {
		return nil, nil, err
	}
	codeFiles := make([]azicliwkscosp.CodeFile, len(files))
	for i, file := range files {
		codeFiles[i] = azicliwkscosp.CodeFile{Type: azicliwkscosp.CodeFileTypePermCode, Path: file}
	}
	suppSchemaFNames := langSpec.GetSupportedSchemaFileNames()
	existingSchemaFiles := []string{}
	for _, schemaFile := range suppSchemaFNames {
		if exists, _ := m.persMgr.CheckPathIfExists(azicliwkspers.WorkspaceDir, schemaFile); exists {
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
	pwd := m.ctx.GetWorkDir()
	normalizedCodeFiles := []azicliwkscosp.CodeFile{}
	for _, codeFile := range codeFiles {
		relativePath, _ := filepath.Rel(pwd, codeFile.Path)
		newCodeFile := azicliwkscosp.CodeFile{Type: codeFile.Type, Path: relativePath}
		normalizedCodeFiles = append(normalizedCodeFiles, newCodeFile)
	}
	normalizedIgnoredCodeFiles := []azicliwkscosp.CodeFile{}
	for _, codeFile := range ignoredCodeFiles {
		relativePath, _ := filepath.Rel(pwd, codeFile.Path)
		newCodeFile := azicliwkscosp.CodeFile{Type: codeFile.Type, Path: relativePath}
		normalizedIgnoredCodeFiles = append(normalizedIgnoredCodeFiles, newCodeFile)
	}
	return normalizedCodeFiles, normalizedIgnoredCodeFiles, nil
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
		multiSecObj, err := absLang.CreateSchemaBlobObjects(path, data)
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
			CodeID:    secObj.GetCodeID(),
			CodeType:  secObj.GetCodeType(),
		}
		if codeFile.HasErrors {
			codeFile.ErrorMessage = azerrors.GetSystemErrorMessage(secObj.GetError())
		} else {
			obj := secObj.GetObject()
			codeFile.OID = obj.GetOID()
			m.cospMgr.SaveCodeSourceObject(obj.GetOID(), obj.GetContent())
		}
		blbCodeFiles = append(blbCodeFiles, *codeFile)
	}
	return blbCodeFiles
}

// blobifyPermSchemaFile blobify a permguard code file.
func (m *WorkspaceManager) blobifyPermCodeFile(absLang azlang.LanguageAbastraction, path string, data []byte, file azicliwkscosp.CodeFile, wkdir string, mode uint32, blbCodeFiles []azicliwkscosp.CodeFile) []azicliwkscosp.CodeFile {
	multiSecObj, err := absLang.CreatePolicyBlobObjects(path, data)
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
			CodeID:    secObj.GetCodeID(),
			CodeType:  secObj.GetCodeType(),
		}
		if codeFile.HasErrors {
			codeFile.ErrorMessage = azerrors.GetSystemErrorMessage(secObj.GetError())
		} else {
			obj := secObj.GetObject()
			codeFile.OID = obj.GetOID()
			m.cospMgr.SaveCodeSourceObject(obj.GetOID(), obj.GetContent())
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
		data, mode, err := m.persMgr.ReadFile(azicliwkspers.WorkspaceDir, path, false)
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
			CodeID:       aztypes.ClassTypeSchema,
			CodeType:     aztypes.ClassTypeSchema,
			ErrorMessage: "permcode: the schema file 'schema.yml' is missing. please ensure there are no duplicate schema files and that the required schema file is present.",
		}
		blbCodeFiles = append(blbCodeFiles, codeFile)
	}
	if err := m.cospMgr.SaveCodeSourceCodeMap(blbCodeFiles); err != nil {
		return "", blbCodeFiles, err
	}
	for _, blobCodeFile := range blbCodeFiles {
		if blobCodeFile.HasErrors {
			return "", blbCodeFiles, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: blobification process failed because of errors in the code files")
		}
	}
	codeObsState, err := m.cospMgr.ConvertCodeFilesToCodeObjectStates(blbCodeFiles)
	if err != nil {
		return "", blbCodeFiles, err
	}
	if err := m.cospMgr.SaveCodeSourceCodeState(codeObsState); err != nil {
		return "", blbCodeFiles, err
	}
	tree, err := azlangobjs.NewTree()
	if err != nil {
		return "", blbCodeFiles, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: tree object cannot be created")
	}
	for _, codeObjState := range codeObsState {
		treeItem, err := azlangobjs.NewTreeEntry(codeObjState.OType, codeObjState.OID, codeObjState.OName, codeObjState.CodeID, codeObjState.CodeType)
		if err != nil {
			return "", nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: tree item cannot be created")
		}
		if err := tree.AddEntry(treeItem); err != nil {
			return "", blbCodeFiles, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: tree item cannot be added to the tree because of errors in the code files")
		}
	}
	treeObj, err := absLang.CreateTreeObject(tree)
	if err != nil {
		return "", blbCodeFiles, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: tree object cannot be created")
	}
	if _, err = m.cospMgr.SaveCodeSourceObject(treeObj.GetOID(), treeObj.GetContent()); err != nil {
		return "", blbCodeFiles, err
	}
	treeID := treeObj.GetOID()
	langSpec := absLang.GetLanguageSpecification()
	if err := m.cospMgr.SaveCodeSourceConfig(treeID, langSpec.GetLanguageName()); err != nil {
		return treeID, blbCodeFiles, err
	}
	return treeID, blbCodeFiles, nil
}

// retrieveCodeMap retrieves the code map.
func (m *WorkspaceManager) retrieveCodeMap() ([]azicliwkscosp.CodeFile, []azicliwkscosp.CodeFile, error) {
	codeFiles, err := m.cospMgr.ReadCodeSourceCodeMap()
	if err != nil {
		return nil, nil, err
	}

	validFiles := []azicliwkscosp.CodeFile{}
	invalidFiles := []azicliwkscosp.CodeFile{}
	duplicateFiles := []azicliwkscosp.CodeFile{}
	nameMap := make(map[string]int)

	for _, codeFile := range codeFiles {
		if codeFile.HasErrors {
			invalidFiles = append(invalidFiles, codeFile)
		} else {
			nameMap[codeFile.OName]++
			if nameMap[codeFile.OName] == 2 {
				duplicateFiles = append(duplicateFiles, codeFile)
			}
			validFiles = append(validFiles, codeFile)
		}
	}

	for _, dupFile := range duplicateFiles {
		dupFile.HasErrors = true
		dupFile.ErrorMessage = "permcode: duplicate object name found in the code files. please ensure that there are no duplicate object names"
		invalidFiles = append(invalidFiles, dupFile)
	}

	return validFiles, invalidFiles, nil
}
