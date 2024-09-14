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

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscosp "github.com/permguard/permguard/internal/cli/workspace/cosp"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
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

// buildOutputForCodeFiles builds the output for the code files.
func buildOutputForCodeFiles(codeFiles []azicliwkscosp.CodeFile, m *WorkspaceManager, out func(map[string]any, string, any, error) map[string]any, output map[string]any) map[string]any {
	if output == nil {
		output = map[string]any{}
	}
	errorsMap := map[string]any{}
	for _, codeFile := range codeFiles {
		if codeFile.HasErrors {
			cFile := codeFile.Path
			cSection := codeFile.Section + 1
			if m.ctx.IsVerboseTerminalOutput() {
				out(output, "refresh", fmt.Sprintf(`Error in file %s, section %s and error message %s.`, aziclicommon.FileText(cFile), aziclicommon.NumberText(cSection), aziclicommon.ErrorText(codeFile.ErrorMessage)), nil)
			}
			if m.ctx.IsJSONOutput() {
				if _, ok := errorsMap[cFile]; !ok {
					errorsMap[cFile] = map[string]any{}
				}
				fileMap := errorsMap[cFile].(map[string]any)
				section := fmt.Sprintf("%d", cSection)
				if _, ok := fileMap[section]; !ok {
					fileMap[section] = map[string]any{}
				}
				sectionMap := fileMap[section].(map[string]any)
				sectionMap["path"] = cFile
				sectionMap["section"] = cSection
				sectionMap["section"] = codeFile.ErrorMessage
			}
		}
	}
	if len(errorsMap) > 0 {
		output["validation_errors"] = errorsMap
	}
	return output
}

// ExecRefresh scans source files in the current directory and synchronizes the local state,
func (m *WorkspaceManager) ExecRefresh(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	return m.execInternalRefresh(false, out)
}

// execInternalRefresh scans source files in the current directory and synchronizes the local state,
func (m *WorkspaceManager) execInternalRefresh(internal bool, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf(ErrMessageCliWorkspaceDirectory, m.getHomeHiddenDir()))
	}
	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	ref, err := m.rfsMgr.GetCurrentHeadRef()
	if err != nil {
		return nil, err
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "Initiating cleanup of the staging area...", nil)
	}
	cleaned, err := m.cleanupStagingArea()
	if err != nil {
		return nil, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		if cleaned {
			out(nil, "refresh", "Staging area cleaned successfully.", nil)
		} else {
			out(nil, "refresh", "The staging area was already clean.", nil)
		}
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
		out(nil, "refresh", "Scanning source files...", nil)
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
		out(nil, "refresh", fmt.Sprintf("Scanned %s %s, selected %s %s, and ignored %s %s.",
			aziclicommon.NumberText(totalCount), fileWord(totalCount), aziclicommon.NumberText(selectedCount), fileWord(selectedCount), aziclicommon.NumberText(ignoredCount), fileWord(ignoredCount)), nil)
		m.printFiles("excluded_files", azicliwkscosp.ConvertCodeFilesToPath(ignoredFiles), out)
		m.printFiles("processed_files", azicliwkscosp.ConvertCodeFilesToPath(selectedFiles), out)
	} else if m.ctx.IsVerboseJSONOutput() {
		output = map[string]any{
			"excluded_files":  azicliwkscosp.ConvertCodeFilesToPath(ignoredFiles),
			"processed_files": azicliwkscosp.ConvertCodeFilesToPath(selectedFiles),
		}
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "Starting blobification process...", nil)
	}
	treeID, codeFiles, err := m.blobifyLocal(selectedFiles, absLang)
	if err != nil {
		output = buildOutputForCodeFiles(codeFiles, m, out, output)
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "refresh", "Blobification process couldn't be completed.", nil)
		}
		if m.ctx.IsTerminalOutput() && !internal {
			out(nil, "", fmt.Sprintf("Your workspace %s has errors.\n", aziclicommon.KeywordText(ref)), nil)
			out(nil, "", "Please validate and fix the errors to proceed.", nil)
		}
		return output, err
	}
	output = buildOutputForCodeFiles(codeFiles, m, out, output)
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "Blobification process completed successfully.", nil)
		out(nil, "refresh", fmt.Sprintf("Tree %s created.", treeID), nil)
	}
	if m.ctx.IsTerminalOutput() && !internal {
		out(nil, "", "Your workspace has been refreshed:\n", nil)
		out(nil, "", fmt.Sprintf("	- repo: %s", aziclicommon.KeywordText(ref)), nil)
		out(nil, "", fmt.Sprintf("	- treeid: %s", aziclicommon.IDText(treeID)), nil)
		out(nil, "", "\n", nil)
		return output, nil
	}
	return output, nil
}

// ExecValidate validates the local state.
func (m *WorkspaceManager) ExecValidate(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf(ErrMessageCliWorkspaceDirectory, m.getHomeHiddenDir()))
	}

	ref, err := m.rfsMgr.GetCurrentHeadRef()
	if err != nil {
		return nil, err
	}

	output, _ := m.execInternalRefresh(true, out)
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "validate", "Retrieving codemap...", nil)
	}
	_, invlsCodeFiles, err := m.retrieveCodeMap()
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "validate", "Codemap could not be retrieved.", nil)
		}
		return output, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "validate", "Codemap retrieved successfully.", nil)
	}

	if len(invlsCodeFiles) == 0 {
		codeStaging, err := m.cospMgr.ReadCodeStagingConfig()
		if err != nil {
			return nil, err
		}
		out(nil, "", "Your workspace is valid:\n", nil)
		out(nil, "", fmt.Sprintf("	- repo: %s", aziclicommon.KeywordText(ref)), nil)
		out(nil, "", fmt.Sprintf("	- treeid: %s", aziclicommon.IDText(codeStaging.TreeID)), nil)
		out(nil, "", "\n", nil)
		return output, nil
	}

	out(nil, "", fmt.Sprintf("Your workspace %s has errors in the following files:\n", aziclicommon.KeywordText(ref)), nil)
	for key := range groupCodeFiles(invlsCodeFiles) {
		out(nil, "", fmt.Sprintf("	- %s", aziclicommon.FileText(key)), nil)
		for _, codeFile := range groupCodeFiles(invlsCodeFiles)[key] {
			if codeFile.OID == "" {
				out(nil, "", fmt.Sprintf("		%s: %s", aziclicommon.NumberText(codeFile.Section+1,), aziclicommon.ErrorText(codeFile.ErrorMessage)), nil)
			} else {
				out(nil, "", fmt.Sprintf("		%s: %s %s", aziclicommon.NumberText(codeFile.Section+1,),
					aziclicommon.KeywordText(codeFile.OID), aziclicommon.ErrorText(codeFile.ErrorMessage)), nil)
			}
		}
	}
	out(nil, "", "\nPlease fix the errors to proceed.", nil)
	return output, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: validation errors found in code files within the workspace. please check the logs for more details.")
}

// ExecObjects manage the object store.
func (m *WorkspaceManager) ExecObjects(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf(ErrMessageCliWorkspaceDirectory, m.getHomeHiddenDir()))
	}
	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	m.cospMgr.CleanStagingArea()

	// TODO: Implement this method

	return nil, nil
}
