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
	"errors"
	"fmt"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/workspace/cosp"
)

// buildOutputForCodeFiles builds the output for the code files.
func buildOutputForCodeFiles(codeFiles []cosp.CodeFile, m *WorkspaceManager, out common.PrinterOutFunc, output map[string]any) map[string]any {
	if output == nil {
		output = map[string]any{}
	}
	errorsMap := map[string]any{}
	for _, codeFile := range codeFiles {
		if !codeFile.HasErrors {
			continue
		}
		cFile := codeFile.Path
		cPartition := codeFile.Partition
		cSection := codeFile.Section + 1
		if m.ctx.IsVerboseTerminalOutput() {
			out(output, "refresh", fmt.Sprintf(`Error in file %s, partition %s, section %s and error message '%s'.`,
				common.FileText(cFile), common.IDText(cPartition), common.NumberText(cSection), common.LogErrorText(codeFile.Error)), nil, true)
		} else if m.ctx.IsJSONOutput() {
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
			sectionMap["partition"] = cPartition
			sectionMap["section"] = cSection
			sectionMap["error"] = codeFile.Error
		}
	}
	if m.ctx.IsJSONOutput() && len(errorsMap) == 0 {
		output["code_files"] = []map[string]any{}
		for _, codeFile := range codeFiles {
			output["code_files"] = append(output["code_files"].([]map[string]any), map[string]any{
				"path":       codeFile.Path,
				"partition":  codeFile.Partition,
				"section":    codeFile.Section + 1,
				"oid":        codeFile.OID,
				"oname":      codeFile.OName,
				"has_errors": codeFile.HasErrors,
				"error":      codeFile.Error,
			})
		}
	}
	if len(errorsMap) > 0 {
		output["validation_errors"] = errorsMap
	}
	return output
}

// ExecRefresh scans source files in the current directory and synchronizes the local state,
func (m *WorkspaceManager) ExecRefresh(out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to refresh the current workspace.", nil, true)
		return output, err
	}
	m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return fail(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return fail(nil, err)
	}
	defer fileLock.Unlock()

	return m.execInternalRefresh(false, out)
}

// execInternalRefresh scans source files in the current directory and synchronizes the local state,
func (m *WorkspaceManager) execInternalRefresh(internal bool, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", "Failed to refresh the current workspace.", nil, true)
		}
		return output, err
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "Initiating cleanup of the local area.", nil, true)
	}
	cleaned, err := m.cleanupLocalArea()
	if err != nil {
		return fail(nil, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		if cleaned {
			out(nil, "refresh", "Local area cleaned successfully.", nil, true)
		} else {
			out(nil, "refresh", "The local area was already clean.", nil, true)
		}
	}
	langPvd, err := m.buildManifestLanguageProvider()
	if err != nil {
		return fail(nil, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "Scanning source files.", nil, true)
	}
	selectedFiles, ignoredFiles, err := m.scanSourceCodeFiles(langPvd)
	if err != nil {
		return fail(nil, err)
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
			common.NumberText(totalCount), fileWord(totalCount), common.NumberText(selectedCount), fileWord(selectedCount), common.NumberText(ignoredCount), fileWord(ignoredCount)), nil, true)
		out(nil, "", "", nil, true)
		m.printFiles("excluded_files", cosp.ConvertCodeFilesToPath(ignoredFiles), out)
		m.printFiles("processed_files", cosp.ConvertCodeFilesToPath(selectedFiles), out)
		out(nil, "", "", nil, true)
	} else if m.ctx.IsVerboseJSONOutput() {
		output = map[string]any{
			"excluded_files":  cosp.ConvertCodeFilesToPath(ignoredFiles),
			"processed_files": cosp.ConvertCodeFilesToPath(selectedFiles),
		}
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "Starting blobification process.", nil, true)
	}
	treeID, codeFiles, err := m.blobifyLocal(selectedFiles, langPvd)
	if err != nil {
		output = buildOutputForCodeFiles(codeFiles, m, out, output)
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "refresh", "Blobification process couldn't be completed.", nil, true)
		}
		if !internal {
			out(nil, "", "Your workspace has errors.", nil, true)
			out(nil, "", "Please validate and fix the errors to proceed.", nil, true)
		}
		return fail(output, err)
	}
	output = buildOutputForCodeFiles(codeFiles, m, out, output)
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "refresh", "Blobification process completed successfully.", nil, true)
		out(nil, "refresh", fmt.Sprintf("New tree created with id: %s.", common.IDText(treeID)), nil, true)
	}
	if !internal {
		out(nil, "", "Your workspace has been refreshed.", nil, true)
		return output, nil
	}
	return output, nil
}

// ExecValidate validates the local state.
func (m *WorkspaceManager) ExecValidate(out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to validate the current workspace.", nil, true)
		return output, err
	}
	m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return fail(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return fail(nil, err)
	}
	defer fileLock.Unlock()

	return m.execInternalValidate(false, out)
}

// execInternalValidate validates the local state.
func (m *WorkspaceManager) execInternalValidate(internal bool, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", "Failed to validate the current workspace.", nil, true)
		}
		return output, err
	}

	output, _ := m.execInternalRefresh(true, out)
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "validate", "Retrieving codemap.", nil, true)
	}

	_, invalidCodeFiles, err := m.retrieveCodeMap()
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "validate", "Codemap could not be retrieved.", nil, true)
		}
		return fail(output, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "validate", "Codemap retrieved successfully.", nil, true)
		out(nil, "validate", "Validation process initiated.", nil, true)
	}
	if len(invalidCodeFiles) == 0 {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "validate", "Validation completed successfully.", nil, true)
		}
		if !internal {
			out(nil, "", "Your workspace has been validated successfully.", nil, true)
		}
		return output, nil
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "validate", "Validation failed. Invalid code files detected.", nil, true)
	}
	if !internal {
		if len(invalidCodeFiles) == 1 {
			out(nil, "", "Your workspace has on error in the following file:\n", nil, true)
		} else {
			out(nil, "", "Your workspace has errors in the following files:\n", nil, true)
		}
		groupedCodeFiles := groupCodeFiles(invalidCodeFiles)
		for key := range groupedCodeFiles {
			out(nil, "", fmt.Sprintf("	- '%s'", common.FileText(key)), nil, true)
			for _, codeFile := range groupedCodeFiles[key] {
				if codeFile.OID == "" {
					out(nil, "", fmt.Sprintf("		%s: %s", common.NumberText(codeFile.Section+1), common.LogErrorText(codeFile.Error)), nil, true)
				} else {
					out(nil, "", fmt.Sprintf("		%s: %s %s", common.NumberText(codeFile.Section+1),
						common.IDText(codeFile.OID), common.NameText(codeFile.OName)), nil, true)
					out(nil, "", fmt.Sprintf("		   %s", common.LogErrorText(codeFile.Error)), nil, true)
				}
			}
		}
		out(nil, "", "\nPlease fix the errors to proceed.", nil, true)
	}
	return fail(output, errors.New("cli: validation errors found in code files within the workspace. please check the logs for more details"))
}
