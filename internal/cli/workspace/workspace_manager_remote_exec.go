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
	azicliwksrepos "github.com/permguard/permguard/internal/cli/workspace/repos"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// ExecCheckoutRepo checks out a repository.
func (m *WorkspaceManager) ExecCheckoutRepo(repoURI string, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to checkout repo %s.", aziclicommon.KeywordText(repoURI)), nil, true)
		return output, err
	}

	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	repoInfo, err := azicliwksrepos.GetRepoInfoFromURI(repoURI)
	if err != nil {
		return failedOpErr(nil, err)
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Initiating remote verification process.", nil, true)
	}
	exist, _ := m.cfgMgr.CheckRepoIfExists(repoURI)
	if exist {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Remote verification failed: repository already exists.", nil, true)
		}
		return failedOpErr(nil, azerrors.WrapSystemError(azerrors.ErrCliRecordExists, fmt.Sprintf("cli: repo %s already exists", repoURI)))
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Remote verified successfully.", nil, true)
	}

	remoteInfo, err := m.cfgMgr.GetRemoteInfo(repoInfo.GetRemote())
	if err != nil {
		return failedOpErr(nil, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Retrieving remote repository information.", nil, true)
	}
	srvRepo, err := m.rmSrvtMgr.GetServerRemoteRepo(repoInfo.GetAccountID(), repoInfo.GetRepo(), remoteInfo.GetServer(), remoteInfo.GetAAPPort(), remoteInfo.GetPAPPort())
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Failed to retrieve remote repository information.", nil, true)
		}
		return failedOpErr(nil, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Remote repository retrieved successfully.", nil, true)
	}
	headInfo, output, err := m.rfsMgr.ExecCheckoutHead(repoInfo.GetRemote(), repoInfo.GetAccountID(), repoInfo.GetRepo(), srvRepo.RepositoryID, srvRepo.Refs, nil, out)
	if err != nil {
		return failedOpErr(nil, err)
	}
	output, err = m.cfgMgr.ExecAddRepo(headInfo.GetRefs(), repoURI, output, out)
	if err != nil && !azerrors.AreErrorsEqual(err, azerrors.ErrCliRecordExists) {
		return failedOpErr(output, err)
	}
	m.logsMgr.Log(repoInfo.GetRemote(), headInfo.GetRefs(), srvRepo.Refs, srvRepo.Refs, fmt.Sprintf("checkout: %s", repoURI))
	return output, nil
}

// ExecPull fetches the latest changes from the remote repo and constructs the remote state.
func (m *WorkspaceManager) ExecPull(out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to pull the repo.", nil, true)
		return output, err
	}

	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	headRef, err := m.rfsMgr.GetCurrentHeadRefs()
	if err != nil || headRef == "" {
		out(nil, "", "Please ensure a valid remote repo is checked out.", nil, true)
		if err == nil {
			err = azerrors.WrapSystemError(azerrors.ErrCliWorkspace, "cli: invalid head refs")
		}
		return failedOpErr(nil, err)
	}

	// TODO: Implement this method

	return nil, nil
}
