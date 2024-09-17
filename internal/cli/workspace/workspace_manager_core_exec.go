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

	azvalidators "github.com/permguard/permguard-core/pkg/extensions/validators"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// codeFileInfo represents info about the code file.
func (m *WorkspaceManager) printFiles(action string, files []string, out func(map[string]any, string, any, error) map[string]any) {
	out(nil, "", fmt.Sprintf("	- %s:", action), nil)
	for _, file := range files {
		out(nil, "", fmt.Sprintf("	  	- %s", aziclicommon.FileText(aziclicommon.FileText(file))), nil)
	}
}

// ExecInitWorkspace initializes the workspace.
func (m *WorkspaceManager) ExecInitWorkspace(language string, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	homeDir := m.getHomeHiddenDir()
	res, err := m.persMgr.CreateDirIfNotExists(azicliwkspers.WorkDir, homeDir)
	if err != nil {
		return nil, err
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	if m.ctx.IsVerboseTerminalOutput(){
		out(nil, "init", fmt.Sprintf("Initializing PermGuard workspace in %s.", aziclicommon.FileText(homeDir)), nil)
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
			if m.ctx.IsVerboseTerminalOutput(){
				out(nil, "init", "Initialization failed.", nil)
			}
			return nil, err
		}
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "init", "Initialization succeeded.", nil)
	}
	var msg string
	var output map[string]any
	if firstInit {
		msg = fmt.Sprintf("Initialized empty permguard repository in %s.", aziclicommon.FileText(homeDir))
	} else {
		msg = fmt.Sprintf("Reinitialized existing permguard repository in %s.", aziclicommon.FileText(homeDir))
	}
	output = out(nil, "", msg, nil)
	if m.ctx.IsJSONOutput() {
		remoteObj := map[string]any{
			"cwd": m.getHomeHiddenDir(),
		}
		output = out(nil, "workspace", remoteObj, nil)
	}
	return output, nil
}

// ExecAddRemote adds a remote.
func (m *WorkspaceManager) ExecAddRemote(remote string, server string, aapPort int, papPort int, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, m.raiseWrongWorkspaceDirError(out)
	}
	if !azvalidators.IsValidHostname(server) {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid server %s", server))
	}
	if !azvalidators.IsValidPort(aapPort) {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid aap port %d", aapPort))
	}
	if !azvalidators.IsValidPort(papPort) {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid pap port %d", papPort))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	output, err := m.cfgMgr.ExecAddRemote(remote, server, aapPort, papPort, nil, out)
	return output, err
}

// ExecRemoveRemote removes a remote.
func (m *WorkspaceManager) ExecRemoveRemote(remote string, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, m.raiseWrongWorkspaceDirError(out)
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	refsInfo, err := m.rfsMgr.GetCurrentHeadRefsInfo()
	if err != nil {
		return nil, err
	}
	if refsInfo.GetRemote() == remote {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspace, fmt.Sprintf("cli: cannot remove the remote used by the currently checked out account %s", remote))
	}
	output, err := m.cfgMgr.ExecRemoveRemote(remote, nil, out)
	return output, err
}

// ExecListRemotes lists the remotes.
func (m *WorkspaceManager) ExecListRemotes(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, m.raiseWrongWorkspaceDirError(out)
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	output, err := m.cfgMgr.ExecListRemotes(nil, out)
	return output, err
}

// ExecListRepos lists the repos.
func (m *WorkspaceManager) ExecListRepos(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, m.raiseWrongWorkspaceDirError(out)
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	refID, err := m.rfsMgr.GetCurrentHeadRefs()
	if err != nil {
		return nil, err
	}
	output, err := m.cfgMgr.ExecListRepos(refID, nil, out)
	return output, err
}
