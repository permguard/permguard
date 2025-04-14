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
	azobjs "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar/authstarmodels/objects"
	azicliwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
)

// getCurrentHeadContext gets the current head context.
func (m *WorkspaceManager) getCurrentHeadContext() (*currentHeadContext, error) {
	headRef, err := m.rfsMgr.GetCurrentHeadRef()
	if err != nil {
		return nil, err
	}
	headRefInfo, err := m.rfsMgr.GetCurrentHeadRefInfo()
	if err != nil {
		return nil, err
	}
	headRefCommitID, err := m.rfsMgr.GetRefCommit(headRef)
	if err != nil {
		return nil, err
	}
	remoteRef, err := m.rfsMgr.GetRefUpstreamRef(headRef)
	if err != nil {
		return nil, err
	}
	remoteRefInfo, err := m.rfsMgr.GetRefInfo(remoteRef)
	if err != nil {
		return nil, err
	}
	remoteRefCommitID, err := m.rfsMgr.GetRefCommit(remoteRef)
	if err != nil {
		return nil, err
	}
	remoteInfo, err := m.cfgMgr.GetRemoteInfo(remoteRefInfo.GetRemote())
	if err != nil {
		return nil, err
	}

	headCtx := &currentHeadContext{
		headRefInfo:    headRefInfo,
		remoteRefInfo:  remoteRefInfo,
		headCommitID:   headRefCommitID,
		remoteCommitID: remoteRefCommitID,
		server:         remoteInfo.GetServer(),
		serverPAPPort:  remoteInfo.GetPAPPort(),
	}
	ledgerID, err := m.rfsMgr.GetRefLedgerID(headRef)
	if err != nil {
		return nil, err
	}
	headCtx.headRefInfo, err = azicliwkscommon.BuildRefInfoFromLedgerID(headRefInfo, ledgerID)
	if err != nil {
		return nil, err
	}

	commit, err := m.rfsMgr.GetRefCommit(headCtx.GetRef())
	if err != nil {
		return nil, err
	}
	headCtx.remoteCommitID = commit

	return headCtx, nil
}

// GetCurrentHeadCommit gets the current head commit.
func (m *WorkspaceManager) GetCurrentHeadCommit(ref string) (*azobjs.Commit, error) {
	remoteCommitID, err := m.rfsMgr.GetRefCommit(ref)
	if err != nil {
		return nil, err
	}
	if remoteCommitID == azobjs.ZeroOID {
		return nil, nil
	}
	remoteCommitObj, err := m.cospMgr.ReadObject(remoteCommitID)
	if err != nil {
		return nil, err
	}
	remoteCommit, err := azobjs.ConvertObjectToCommit(remoteCommitObj)
	if err != nil {
		return nil, err
	}
	return remoteCommit, nil
}

// GetCurrentHeadTree gets the current head tree.
func (m *WorkspaceManager) GetCurrentHeadTree(ref string) (*azobjs.Tree, error) {
	commit, err := m.GetCurrentHeadCommit(ref)
	if err != nil {
		return nil, err
	}
	if commit == nil {
		return nil, nil
	}
	treeObj, err := m.cospMgr.ReadObject(commit.GetTree())
	if err != nil {
		return nil, err
	}
	tree, err := azobjs.ConvertObjectToTree(treeObj)
	if err != nil {
		return nil, err
	}
	return tree, nil
}
