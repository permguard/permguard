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
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlang "github.com/permguard/permguard/pkg/core/languages"
)

// blobifyLocal scans source files and creates a blob for each object.
func (m *WorkspaceManager) blobifyLocal(absLang azlang.LanguageAbastraction) (string, error) {
	exts := absLang.GetFileExtensions()
	files, err := m.persMgr.ListFiles(true, "../", exts, []string{hiddenDir})
	if err != nil {
		return "", err
	}
	if len(files) == 0 {
		return "", azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, "no source files found")
	}
	for _, file := range files {
		data, _, err := m.persMgr.ReadFile(false, file)
		if err != nil {
			return "", err
		}
		objs, err := absLang.CreateBlobObjects(data)
		if err != nil {
			return "", nil
		}
		for _, obj := range objs {
			m.persMgr.WriteBinaryFile(true, obj.OID, obj.Content, 0644)
		}
	}
	return "", nil
}

// buildLocalState builds the local state.
func (m *WorkspaceManager) buildLocalState(absLang azlang.LanguageAbastraction, commit string) error {
	// TODO: Implement this method
	return nil
}
