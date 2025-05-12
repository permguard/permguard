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
	"path/filepath"
	"strings"

	"github.com/permguard/permguard/internal/cli/workspace/cosp"
	"github.com/permguard/permguard/internal/cli/workspace/persistence"
	cerrors "github.com/permguard/permguard/pkg/core/errors"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/authz/languages/types"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// groupCodeFiles groups the code files.
func groupCodeFiles(codeFiles []cosp.CodeFile) map[string][]cosp.CodeFile {
	grouped := map[string][]cosp.CodeFile{}
	for _, codeFile := range codeFiles {
		if _, ok := grouped[codeFile.Path]; !ok {
			grouped[codeFile.Path] = []cosp.CodeFile{}
		}
		grouped[codeFile.Path] = append(grouped[codeFile.Path], codeFile)
	}
	return grouped
}

// cleanupLocalArea cleans up the local area.
func (m *WorkspaceManager) cleanupLocalArea() (bool, error) {
	return m.cospMgr.CleanCodeSource()
}

// scanSourceCodeFiles scans the source code and schema files across all supported partitions.
// It returns two lists: the included files and the ignored files.
func (m *WorkspaceManager) scanSourceCodeFiles(langPvd *ManifestLanguageProvider) ([]cosp.CodeFile, []cosp.CodeFile, error) {
	partitions := langPvd.GetPartitions()
	if len(partitions) == 0 {
		return nil, nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrCliWorkspace, "no partitions are supported")
	}

	var scanIncludedFiles, scanIgnoredFiles []cosp.CodeFile
	workDir := m.ctx.GetWorkDir()

	for _, partition := range partitions {
		absLang, err := langPvd.GetAbstractLanguage(partition)
		if err != nil {
			return nil, nil, err
		}

		codeFileExts := absLang.GetPolicyFileExtensions()
		schemaFileNames := absLang.GetSchemaFileNames()

		ignoredPartitionPaths := []string{}
		if partition == "/" {
			for _, subPart := range partitions {
				if subPart == partition {
					continue
				}
				subPart = strings.TrimPrefix(subPart, "/")
				ignoredPartitionPaths = append(ignoredPartitionPaths, filepath.Join(".", subPart))
			}
		}

		// Scan code files
		codeIgnorePatterns := append([]string{hiddenIgnoreFile, hiddenDir, gitDir, gitIgnoreFile}, schemaFileNames...)
		codeIgnorePatterns = append(codeIgnorePatterns, ignoredPartitionPaths...)
		codeIncluded, codeIgnored, err := m.scanByKind(partition, cosp.CodeFileTypeOfCodeType, codeFileExts, codeIgnorePatterns, workDir)
		if err != nil {
			return nil, nil, err
		}
		scanIncludedFiles = append(scanIncludedFiles, codeIncluded...)
		scanIgnoredFiles = append(scanIgnoredFiles, codeIgnored...)

		// Scan schema files
		schemaIgnorePatterns := append([]string{hiddenIgnoreFile, hiddenDir, gitDir, gitIgnoreFile}, codeFileExts...)
		schemaIgnorePatterns = append(schemaIgnorePatterns, ignoredPartitionPaths...)
		schemaIncluded, schemaIgnored, err := m.scanByKind(partition, cosp.CodeFileOfSchemaType, schemaFileNames, schemaIgnorePatterns, workDir)
		if err != nil {
			return nil, nil, err
		}
		scanIncludedFiles = append(scanIncludedFiles, schemaIncluded...)
		scanIgnoredFiles = append(scanIgnoredFiles, schemaIgnored...)
	}

	return scanIncludedFiles, scanIgnoredFiles, nil
}

// scanByKind scans and filters files of a specific kind (e.g., code or schema) for a given partition.
// It returns the included files and the ignored files, each annotated with partition and kind.
func (m *WorkspaceManager) scanByKind(partition string, kind string, extensions, ignorePatterns []string, workDir string) ([]cosp.CodeFile, []cosp.CodeFile, error) {
	partitionPath := filepath.Join(".", strings.TrimPrefix(partition, "/"))
	includedPaths, ignoredPaths, err := m.persMgr.ScanAndFilterFiles(persistence.WorkspaceDir, partitionPath, extensions, ignorePatterns, hiddenIgnoreFile)
	if err != nil {
		return nil, nil, err
	}

	var includedFiles, ignoredFiles []cosp.CodeFile
	for _, absPath := range includedPaths {
		relPath, err := filepath.Rel(workDir, absPath)
		if err != nil {
			return nil, nil, cerrors.WrapHandledSysError(cerrors.ErrCliWorkspace, fmt.Errorf("failed to compute relative path for included file %q: %w", absPath, err))
		}
		includedFiles = append(includedFiles, cosp.CodeFile{
			Partition: partition,
			Kind:      kind,
			Path:      relPath,
		})
	}

	for _, absPath := range ignoredPaths {
		relPath, err := filepath.Rel(workDir, absPath)
		if err != nil {
			return nil, nil, cerrors.WrapHandledSysError(cerrors.ErrCliWorkspace, fmt.Errorf("failed to compute relative path for ignored file %q: %w", absPath, err))
		}
		ignoredFiles = append(ignoredFiles, cosp.CodeFile{
			Partition: partition,
			Kind:      kind,
			Path:      relPath,
		})
	}

	return includedFiles, ignoredFiles, nil
}

// blobifyPermSchemaFile processes a PermGuard schema file.
// It enforces that only one schema file is allowed per workspace.
func (m *WorkspaceManager) blobifyPermSchemaFile(langPvd *ManifestLanguageProvider, partition, path, wkdir string, mode uint32, blobifiedCodeFiles []cosp.CodeFile, data []byte, file cosp.CodeFile) ([]cosp.CodeFile, error) {
	absLang, err := langPvd.GetAbstractLanguage(file.Partition)
	if err != nil {
		return nil, err
	}
	lang, err := langPvd.GetLanguage(file.Partition)
	if err != nil {
		return nil, err
	}
	multiSecObj, err := absLang.CreateSchemaBlobObjects(lang, partition, path, data)
	if err != nil {
		codeFile := cosp.CodeFile{
			Partition:    partition,
			Kind:         file.Kind,
			Path:         strings.TrimPrefix(path, wkdir),
			Section:      0,
			Mode:         mode,
			HasErrors:    true,
			ErrorMessage: err.Error(),
		}
		return append(blobifiedCodeFiles, codeFile), nil
	}

	// Only one section is expected in schema files
	secObj := multiSecObj.GetSectionObjects()[0]
	codeFile := m.buildCodeFileFromSection(secObj, file, path, wkdir, mode)
	return append(blobifiedCodeFiles, codeFile), nil
}

// blobifyLanguageFile processes a PermGuard policy file containing multiple logical sections.
func (m *WorkspaceManager) blobifyLanguageFile(langPvd *ManifestLanguageProvider, partition string, path string, data []byte,
	file cosp.CodeFile, wkdir string, mode uint32, blobifiedCodeFiles []cosp.CodeFile) ([]cosp.CodeFile, error) {

	absLang, err := langPvd.GetAbstractLanguage(file.Partition)
	if err != nil {
		return nil, err
	}
	lang, err := langPvd.GetLanguage(file.Partition)
	if err != nil {
		return nil, err
	}
	multiSecObj, err := absLang.CreatePolicyBlobObjects(lang, partition, path, data)
	if err != nil {
		codeFile := cosp.CodeFile{
			Partition:    partition,
			Kind:         file.Kind,
			Path:         strings.TrimPrefix(path, wkdir),
			Section:      -1,
			Mode:         mode,
			HasErrors:    true,
			ErrorMessage: err.Error(),
		}
		return append(blobifiedCodeFiles, codeFile), nil
	}

	for _, secObj := range multiSecObj.GetSectionObjects() {
		codeFile := m.buildCodeFileFromSection(secObj, file, path, wkdir, mode)
		blobifiedCodeFiles = append(blobifiedCodeFiles, codeFile)
	}
	return blobifiedCodeFiles, nil
}

// buildCodeFileFromSection builds a CodeFile from a given SectionObject with metadata, errors and OID assignment.
func (m *WorkspaceManager) buildCodeFileFromSection(secObj *objects.SectionObject, inputFile cosp.CodeFile, path, wkdir string, mode uint32) cosp.CodeFile {
	codeFile := cosp.CodeFile{
		Partition:       secObj.GetPartition(),
		Kind:            inputFile.Kind,
		Path:            strings.TrimPrefix(path, wkdir),
		Section:         secObj.GetNumberOfSection(),
		Mode:            mode,
		HasErrors:       secObj.GetError() != nil,
		OType:           secObj.GetObjectType(),
		OName:           secObj.GetObjectName(),
		CodeID:          secObj.GetCodeID(),
		CodeType:        secObj.GetCodeType(),
		Language:        secObj.GetLanguage(),
		LanguageVersion: secObj.GetLanguageVersion(),
		LanguageType:    secObj.GetLanguageType(),
	}

	if codeFile.HasErrors {
		err := secObj.GetError()
		if sysErr := cerrors.ConvertToSystemError(err); sysErr != nil {
			codeFile.ErrorMessage = sysErr.Message()
		} else {
			codeFile.ErrorMessage = err.Error()
		}
	} else {
		obj := secObj.GetObject()
		codeFile.OID = obj.GetOID()
		m.cospMgr.SaveCodeSourceObject(obj.GetOID(), obj.GetContent())
	}

	return codeFile
}

// blobifyLocal processes source files and converts them into blobs, handling both code and schema types.
// It ensures that only one schema file exists per partition and constructs a tree object to represent the structure.
func (m *WorkspaceManager) blobifyLocal(codeFiles []cosp.CodeFile, langPvd *ManifestLanguageProvider) (string, []cosp.CodeFile, error) {
	blobifiedCodeFiles := []cosp.CodeFile{}
	partitionSchemas := map[string]int{}

	for _, file := range codeFiles {
		wkdir := m.ctx.GetWorkDir()
		path := file.Path

		// Read file content and mode from the workspace
		var err error
		var data []byte
		var mode uint32
		data, mode, err = m.persMgr.ReadFile(persistence.WorkspaceDir, path, false)
		if err != nil {
			return "", nil, err
		}

		partition := file.Partition

		// Process code files using the language provider
		switch file.Kind {
		case cosp.CodeFileTypeOfCodeType:
			blobifiedCodeFiles, err = m.blobifyLanguageFile(langPvd, partition, path, data, file, wkdir, mode, blobifiedCodeFiles)
			if err != nil {
				return "", nil, err
			}
		case cosp.CodeFileOfSchemaType:
			// Ensure only one schema file per partition
			partitionSchemas[file.Partition]++
			if partitionSchemas[file.Partition] > 1 {
				codeFile := cosp.CodeFile{
					Partition:    partition,
					Path:         strings.TrimPrefix(path, wkdir),
					Section:      0,
					Mode:         mode,
					HasErrors:    true,
					ErrorMessage: "language: only one schema file is permitted in the workspace. Please ensure there are no duplicate schema files.",
				}
				blobifiedCodeFiles = append(blobifiedCodeFiles, codeFile)
			} else {
				blobifiedCodeFiles, err = m.blobifyPermSchemaFile(langPvd, partition, path, wkdir, mode, blobifiedCodeFiles, data, file)
				if err != nil {
					return "", nil, err
				}
			}
		default:
			return "", nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrCliFileOperation, "file type is not supported")
		}
	}

	// Validate that required schema files are present per partition
	for partition, schemaCount := range partitionSchemas {
		if schemaCount > 0 {
			continue
		}
		absLang, err := langPvd.GetAbstractLanguage(partition)
		if err != nil {
			return "", nil, err
		}
		schemaFileNames := absLang.GetSchemaFileNames()
		if len(schemaFileNames) > 0 {
			schemaFileName := schemaFileNames[0]
			codeFile := cosp.CodeFile{
				Partition:    partition,
				Path:         m.persMgr.GetRelativeDir(persistence.WorkspaceDir, schemaFileName),
				Section:      0,
				Mode:         0,
				HasErrors:    true,
				CodeID:       types.ClassTypeSchema,
				CodeType:     types.ClassTypeSchema,
				ErrorMessage: fmt.Sprintf("language: the schema file '%s' is missing. Please ensure there are no duplicate schema files and that the required schema file is present.", schemaFileName),
			}
			blobifiedCodeFiles = append(blobifiedCodeFiles, codeFile)
		}
	}

	// Save code source map
	var err error
	if err = m.cospMgr.SaveCodeSourceCodeMap(blobifiedCodeFiles); err != nil {
		return "", blobifiedCodeFiles, err
	}

	// Abort if any file has errors
	for _, file := range blobifiedCodeFiles {
		if file.HasErrors {
			return "", blobifiedCodeFiles, cerrors.WrapSystemErrorWithMessage(cerrors.ErrCliFileOperation, "blobification process failed due to code file errors")
		}
	}

	// Convert code files to code object states
	var codeObsState []cosp.CodeObjectState
	codeObsState, err = m.cospMgr.ConvertCodeFilesToCodeObjectStates(blobifiedCodeFiles)
	if err != nil {
		return "", blobifiedCodeFiles, err
	}

	// Save the object state
	if err = m.cospMgr.SaveCodeSourceCodeState(codeObsState); err != nil {
		return "", blobifiedCodeFiles, err
	}

	// Build a tree from object states
	var tree *objects.Tree
	tree, err = objects.NewTree()
	if err != nil {
		return "", blobifiedCodeFiles, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliFileOperation, "tree object cannot be created", err)
	}
	for _, obj := range codeObsState {
		var entry *objects.TreeEntry
		entry, err = objects.NewTreeEntry(obj.Partition, obj.OType, obj.OID, obj.OName, obj.CodeID, obj.CodeType, obj.Language, obj.LanguageVersion, obj.LanguageType)
		if err != nil {
			return "", nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliFileOperation, "tree item cannot be created", err)
		}
		if err = tree.AddEntry(entry); err != nil {
			return "", blobifiedCodeFiles, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliFileOperation, "tree item cannot be added due to file errors", err)
		}
	}

	// Create tree object and persist it
	var treeObj *objects.Object
	treeObj, err = objects.CreateTreeObject(tree)
	if err != nil {
		return "", blobifiedCodeFiles, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliFileOperation, "tree object creation failed", err)
	}
	if _, err := m.cospMgr.SaveCodeSourceObject(treeObj.GetOID(), treeObj.GetContent()); err != nil {
		return "", blobifiedCodeFiles, err
	}

	// Save tree configuration
	treeID := treeObj.GetOID()
	if err := m.cospMgr.SaveCodeSourceConfig(treeID); err != nil {
		return treeID, blobifiedCodeFiles, err
	}

	return treeID, blobifiedCodeFiles, nil
}

// retrieveCodeMap loads the code map and separates valid and invalid files.
// A file is considered invalid if it has explicit errors or if its object name is duplicated.
func (m *WorkspaceManager) retrieveCodeMap() ([]cosp.CodeFile, []cosp.CodeFile, error) {
	codeFiles, err := m.cospMgr.ReadCodeSourceCodeMap()
	if err != nil {
		return nil, nil, err
	}

	validFiles := []cosp.CodeFile{}
	invalidFiles := []cosp.CodeFile{}
	nameCount := make(map[string]int)

	// First pass: count names and collect explicit errors
	for _, file := range codeFiles {
		if file.HasErrors {
			invalidFiles = append(invalidFiles, file)
		} else {
			nameCount[file.OName]++
		}
	}

	// Second pass: detect duplicates and separate valid/invalid
	for _, file := range codeFiles {
		if file.HasErrors {
			continue // already added to invalidFiles
		}

		if nameCount[file.OName] > 1 {
			// Duplicate object name found
			file.HasErrors = true
			file.ErrorMessage = "language: duplicate object name found in the code files. please ensure that there are no duplicate object names"
			invalidFiles = append(invalidFiles, file)
		} else {
			validFiles = append(validFiles, file)
		}
	}

	return validFiles, invalidFiles, nil
}
