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

	azicliwkscosp "github.com/permguard/permguard/internal/cli/workspace/cosp"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// buildOutputForCodeFiles builds the output for the code files.
func buildOutputForCodeFiles(codeFiles []azicliwkscosp.CodeFile, m *WorkspaceManager, out func( map[string]any,  string,  any,  error) map[string]any, output map[string]any) (map[string]any) {
	for _, codeFile := range codeFiles {
		errorsMap := map[string]any{}
		if codeFile.HasErrors {
			if m.ctx.IsVerboseTerminalOutput() {
				out(output, "refresh", nil, fmt.Errorf("refresh: error in file %s: %s", codeFile.Path, codeFile.ErrorMessage))
			}
			if m.ctx.IsVerboseJSONOutput() {
				errorsMap[codeFile.Path] = codeFile.ErrorMessage
			}
		}
		if m.ctx.IsVerboseJSONOutput() {
			output["invalid_files"] = errorsMap
		}
	}
	return output
}

// ExecRefresh scans source files in the current directory and synchronizes the local state,
func (m *WorkspaceManager) ExecRefresh(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf(ErrMessageCliWorkspaceDirectory, m.getHomeHiddenDir()))
	}
	returnRefreshError := func (err error) (error) {
		return azerrors.WrapMessageError(err, nil, "refresh")
	}
	fileLock, err := m.tryLock()
	if err != nil {
		return nil, returnRefreshError(err)
	}
	defer fileLock.Unlock()

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "initiating cleanup of the staging area...", nil)
	}
	cleaned, err := m.cleanupStagingArea()
	if err != nil {
		return nil, returnRefreshError(err)
	}
	if !cleaned && m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "the staging area was already clean", nil)
	}

	lang, err := m.cfgMgr.GetLanguage()
	if err != nil {
		return nil, returnRefreshError(err)
	}
	absLang, err := m.langFct.CreateLanguageAbastraction(lang)
	if err != nil {
		return nil, returnRefreshError(err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "scanning source files...", nil)
	}
	selectedFiles, ignoredFiles, err := m.scanSourceCodeFiles(absLang)
	if err != nil {
		return nil, returnRefreshError(err)
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
		m.printFiles("ignored", azicliwkscosp.ConvertCodeFilesToPath(ignoredFiles), out)
		m.printFiles("selected", azicliwkscosp.ConvertCodeFilesToPath(selectedFiles), out)
	} else if m.ctx.IsJSONOutput() {
		output = map[string]any{
			"ignored":  azicliwkscosp.ConvertCodeFilesToPath(ignoredFiles),
			"selected": azicliwkscosp.ConvertCodeFilesToPath(selectedFiles),
		}
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "starting blobification process...", nil)
	}
	treeID, codeFiles, err := m.blobifyLocal(selectedFiles, absLang)
	if err != nil {
		output = buildOutputForCodeFiles(codeFiles, m, out, output)
		return output, returnRefreshError(err)
	}
	output = buildOutputForCodeFiles(codeFiles, m, out, output)
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "blobification process completed successfully", nil)
		out(nil, "refresh", fmt.Sprintf("tree %s created", treeID), nil)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "initializing local state build...", nil)
	}
	err = m.buildLocalState(treeID, absLang)
	if err != nil {
		return output, returnRefreshError(err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "local state build completed", nil)
	}
	return output, nil
}

// ExecValidate validates the local state.
func (m *WorkspaceManager) ExecValidate(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf(ErrMessageCliWorkspaceDirectory, m.getHomeHiddenDir()))
	}
	returnValidateError := func (err error) (error) {
		return azerrors.WrapMessageError(err, nil, "validate")
	}
	fileLock, err := m.tryLock()
	if err != nil {
		return nil, returnValidateError(err)
	}
	defer fileLock.Unlock()

	// TODO: Implement this method

	return nil, nil
}

// ExecObjects manage the object store.
func (m *WorkspaceManager) ExecObjects(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf(ErrMessageCliWorkspaceDirectory, m.getHomeHiddenDir()))
	}
	returnObjectsError := func (err error) (error) {
		return azerrors.WrapMessageError(err, nil, "objects")
	}
	fileLock, err := m.tryLock()
	if err != nil {
		return nil, returnObjectsError(err)
	}
	defer fileLock.Unlock()

	// TODO: Implement this method

	return nil, nil
}
