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
	//azerrors "github.com/permguard/permguard/pkg/core/errors"

	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azlang "github.com/permguard/permguard/pkg/core/languages"
)

// codeFileInfo represents info about the code file.
type codeFileInfo struct {
	Path 			string
	OID 			string
	OType 			string
	State 			string
	Section 		int
	ErrorMessage	bool
}

// convertCodeFilesToPath converts code files to paths.
func convertCodeFilesToPath(files []codeFileInfo) []string {
	paths := make([]string, len(files))
	for i, file := range files {
		paths[i] = file.Path
	}
	return paths
}

// scanSourceCodeFiles scans the source code files.
func (m *WorkspaceManager) scanSourceCodeFiles(absLang azlang.LanguageAbastraction) ([]codeFileInfo, []codeFileInfo, error) {
	exts := absLang.GetFileExtensions()
	ignorePatterns := []string {hiddenIgnoreFile, schemaYAMLFile, schemaYMLFile, hiddenDir, gitDir, gitIgnoreFile}
	files, ignoredFiles, err := m.persMgr.ScanAndFilterFiles(azicliwkspers.WorkspaceDir, exts, ignorePatterns, hiddenIgnoreFile)
	if err != nil {
		return nil, nil, err
	}
	codeFiles := make([]codeFileInfo, len(files))
	for i, file := range files {
		codeFiles[i] = codeFileInfo{Path: file}
	}
	ignoredCodeFiles := make([]codeFileInfo, len(ignoredFiles))
	for i, file := range ignoredFiles {
		ignoredCodeFiles[i] = codeFileInfo{Path: file}
	}
	return codeFiles, ignoredCodeFiles, nil
}

// blobifyLocal scans source files and creates a blob for each object.
func (m *WorkspaceManager) blobifyLocal(codeFileInfos []codeFileInfo, absLang azlang.LanguageAbastraction) (string, error) {
	for _, file := range codeFileInfos {
		path := file.Path
		data, err := m.persMgr.ReadFile(azicliwkspers.WorkDir, path)
		if err != nil {
			return "", err
		}
		multiSecObj, err := absLang.CreateBlobObjects(path, data)
		if err != nil {
			continue
		}
		secObjs := multiSecObj.GetSectionObjectInfos()
		for _, secObj := range secObjs {
			obj := secObj.GetObject()
			m.persMgr.WriteBinaryFile(azicliwkspers.WorkspaceDir, obj.GetOID(), obj.GetContent(), 0644)
		}
	}
	return "", nil
}

// buildLocalState builds the local state.
func (m *WorkspaceManager) buildLocalState(absLang azlang.LanguageAbastraction, commit string) error {
	// TODO: Implement this method
	return nil
}
