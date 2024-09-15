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

	azicliwksvals "github.com/permguard/permguard/internal/cli/workspace/validators"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// ExecCheckoutRepo checks out a repository.
func (m *WorkspaceManager) ExecCheckoutRepo(repoURI string, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, m.raiseWrongWorkspaceDirError(out)
	}

	repoInfo, err := azicliwksvals.ExtractFromRepoURI(repoURI)
	if err != nil {
		return nil, err
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Initiating remote verification process.", nil)
	}
	repo, _ := m.cfgMgr.GetRepo(repoURI)
	if repo != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Remote verification failed: repository already exists.", nil)
		}
		return nil, azerrors.WrapSystemError(azerrors.ErrCliRecordExists, fmt.Sprintf("cli: repository %s already exists", repoURI))
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Remote verified successfully.", nil)
	}

	cfgRemote, err := m.cfgMgr.GetRemote(repoInfo.Remote)
	if err != nil {
		return nil, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Retrieving remote repository information.", nil)
	}
	srvRepo, err := m.rmSrvtMgr.GetServerRemoteRepo(repoInfo.AccountID, repoInfo.Repo, cfgRemote.Server, cfgRemote.AAPPort, cfgRemote.PAPPort)
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Failed to retrieve remote repository information.", nil)
		}
		return nil, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Remote repository retrieved successfully.", nil)
	}
	ref, refID, output, err := m.rfsMgr.CheckoutHead(repoInfo.Remote, repoInfo.AccountID, repoInfo.Repo, srvRepo.Refs, nil, out)
	if err != nil {
		return nil, err
	}
	output, err = m.cfgMgr.ExecAddRepo(repoInfo.Remote, repoInfo.AccountID, repoInfo.Repo, ref, refID, output, out)
	if err != nil && !azerrors.AreErrorsEqual(err, azerrors.ErrCliRecordExists) {
		return nil, err
	}
	m.logsMgr.Log(repoInfo.Remote, refID, srvRepo.Refs, srvRepo.Refs, fmt.Sprintf("checkout: %s", repoURI))
	return output, nil
}

// ExecPull fetches the latest changes from the remote repo and constructs the remote state.
func (m *WorkspaceManager) ExecPull(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, m.raiseWrongWorkspaceDirError(out)
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	// TODO: Implement this method

	return nil, nil
}
