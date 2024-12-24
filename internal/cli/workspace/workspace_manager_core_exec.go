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

	azvalidators "github.com/permguard/permguard-core/pkg/extensions/validators"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// codeFileInfo represents info about the code file.
func (m *WorkspaceManager) printFiles(action string, files []string, out aziclicommon.PrinterOutFunc) {
	out(nil, "", fmt.Sprintf("	- %s:", action), nil, true)
	for _, file := range files {
		out(nil, "", fmt.Sprintf("	  	- '%s'", aziclicommon.FileText(aziclicommon.FileText(file))), nil, true)
	}
}

// ExecPrintContext prints the context.
func (m *WorkspaceManager) ExecPrintContext(output map[string]any, out aziclicommon.PrinterOutFunc) map[string]any {
	if !m.ctx.IsVerboseTerminalOutput() {
		return output
	}
	context := m.persMgr.GetContext()
	for key, value := range context {
		out(nil, "context", fmt.Sprintf("%s '%s'.", key, aziclicommon.FileText(value)), nil, true)

	}
	return output
}

// ExecInitWorkspace initializes the workspace.
func (m *WorkspaceManager) ExecInitWorkspace(language string, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to initialize the workspace", nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	homeDir := m.getHomeHiddenDir()
	res, err := m.persMgr.CreateDirIfNotExists(azicliwkspers.WorkDir, homeDir)
	if err != nil {
		return failedOpErr(nil, err)
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "init", fmt.Sprintf("Initializing Permguard workspace in '%s'.", aziclicommon.FileText(homeDir)), nil, true)
	}
	firstInit := true
	if !res {
		firstInit = false
	}
	initializers := []func(string) error{
		m.logsMgr.ExecInitalize,
		m.cfgMgr.ExecInitialize,
		m.rfsMgr.ExecInitalize,
		m.cospMgr.ExecInitalize,
	}
	for _, initializer := range initializers {
		err := initializer(language)
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "init", "Initialization failed.", nil, true)
			}
			return failedOpErr(nil, err)
		}
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "init", "Initialization succeeded.", nil, true)
	}
	var msg string
	if firstInit {
		msg = fmt.Sprintf("Initialized empty permguard ledger in '%s'.", aziclicommon.FileText(m.getHomeDir()))
	} else {
		msg = fmt.Sprintf("Reinitialized existing permguard ledger in '%s'.", aziclicommon.FileText(m.getHomeDir()))
	}
	out(nil, "", msg, nil, true)
	output = map[string]any{}
	absPath := m.getHomeDir()
	if !filepath.IsAbs(absPath) {
		absPath, _ = filepath.Abs(absPath)
	}
	if m.ctx.IsJSONOutput() {
		remoteObj := map[string]any{
			"root": absPath,
			"policy_engine": map[string]any{
				"language": language,
			},
		}
		output = out(nil, "workspace", remoteObj, nil, true)
	}
	return output, nil
}

// execInternalAddRemote adds a remote.
func (m *WorkspaceManager) execInternalAddRemote(internal bool, remote string, server string, aapPort int, papPort int, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", fmt.Sprintf("Failed to add remote %s.", aziclicommon.KeywordText(remote)), nil, true)
		}
		return output, err
	}

	if !azvalidators.IsValidHostname(server) {
		return failedOpErr(nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid server %s", server)))
	}
	if !azvalidators.IsValidPort(aapPort) {
		return failedOpErr(nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid aap port %d", aapPort)))
	}
	if !azvalidators.IsValidPort(papPort) {
		return failedOpErr(nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid pap port %d", papPort)))
	}

	output, err := m.cfgMgr.ExecAddRemote(remote, server, aapPort, papPort, nil, out)
	if err != nil {
		return failedOpErr(output, err)
	}
	return output, nil
}

// ExecAddRemote adds a remote.
func (m *WorkspaceManager) ExecAddRemote(remote string, server string, aapPort int, papPort int, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to add remote %s.", aziclicommon.KeywordText(remote)), nil, true)
		return output, err
	}
	m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	return m.execInternalAddRemote(false, remote, server, aapPort, papPort, out)
}

// ExecRemoveRemote removes a remote.
func (m *WorkspaceManager) ExecRemoveRemote(remote string, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to remove remote %s.", aziclicommon.KeywordText(remote)), nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	refInfo, err := m.rfsMgr.GetCurrentHeadRefInfo()
	if err != nil {
		return failedOpErr(nil, err)
	}
	if refInfo != nil && refInfo.GetRemote() == remote {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "remote", "Failed to delete remote: it is associated with the current HEAD.", nil, true)
		}
		return failedOpErr(nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspace, fmt.Sprintf("cli: cannot remove the remote used by the currently checked out application %s", remote)))
	}
	output, err = m.cfgMgr.ExecRemoveRemote(remote, nil, out)
	return output, err
}

// ExecListRemotes lists the remotes.
func (m *WorkspaceManager) ExecListRemotes(out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to list remotes.", nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	output, err = m.cfgMgr.ExecListRemotes(nil, out)
	return output, err
}

// ExecListRepos lists the ledgers.
func (m *WorkspaceManager) ExecListRepos(out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to list ledgers.", nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	output, err = m.cfgMgr.ExecListRepos(nil, out)
	return output, err
}
