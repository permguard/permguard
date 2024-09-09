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

	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// ExecRefresh scans source files in the current directory and synchronizes the local state,
func (m *WorkspaceManager) ExecRefresh(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf(ErrMessageCliWorkspaceDirectory, m.getHomeHiddenDir()))
	}
	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "initiating cleanup of the staging area...", nil)
	}

	cleaned, err := m.cleanupStagingArea()
	if err != nil {
		return nil, err
	}
	if !cleaned && m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "the staging area was already clean", nil)
	}

	lang, err := m.cfgMgr.GetLanguage()
	if err != nil {
		return nil, err
	}
	absLang, err := m.langFct.CreateLanguageAbastraction(lang)
	if err != nil {
		return nil, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "scanning source files...", nil)
	}
	selectedFiles, ignoredFiles, err := m.scanSourceCodeFiles(absLang)
 	if err != nil {
		return nil, err
	}
	var output map[string]any
	if m.ctx.IsVerboseTerminalOutput() {
		selectedCount := len(selectedFiles)
		ignoredCount := len(ignoredFiles)
		totalCount := selectedCount + ignoredCount
		fileWord := func(count int) string {
			if count == 1 {
				return "item"
			}
			return "items"
		}
		out(nil, "refresh", fmt.Sprintf("scanned %d %s, selected %d %s, and ignored %d %s",
			totalCount, fileWord(totalCount), selectedCount, fileWord(selectedCount), ignoredCount, fileWord(ignoredCount)), nil)
		m.printFiles("ignored", convertCodeFilesToPath(ignoredFiles), out)
		m.printFiles("selected", convertCodeFilesToPath(selectedFiles), out)
	} else if m.ctx.IsJSONOutput() {
		output = map[string]any{
			"ignored":  convertCodeFilesToPath(ignoredFiles),
			"selected": convertCodeFilesToPath(selectedFiles),
		}
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "blobify", "starting blobify operation...", nil)
	}
	if _, _, err := m.blobifyLocal(selectedFiles, absLang); err != nil {
		return nil, err
	}
	return output, nil
}

// ExecValidate validates the local state.
func (m *WorkspaceManager) ExecValidate(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf(ErrMessageCliWorkspaceDirectory, m.getHomeHiddenDir()))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	// TODO: Implement this method

	return nil, nil
}

// ExecDiff compares the local state with the remote state to identify differences.
func (m *WorkspaceManager) ExecDiff(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf(ErrMessageCliWorkspaceDirectory, m.getHomeHiddenDir()))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	// TODO: Implement this method

	return nil, nil
}
