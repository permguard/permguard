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
	"github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// currentHeadContext gets the current head context.
func (m *Manager) currentHeadContext() (*currentHeadContext, error) {
	headRef, err := m.rfsMgr.CurrentHeadRef()
	if err != nil {
		return nil, err
	}
	headRefInfo, err := m.rfsMgr.CurrentHeadRefInfo()
	if err != nil {
		return nil, err
	}
	headRefCommitID, err := m.rfsMgr.RefCommit(headRef)
	if err != nil {
		return nil, err
	}
	remoteRef, err := m.rfsMgr.RefUpstreamRef(headRef)
	if err != nil {
		return nil, err
	}
	remoteRefInfo, err := m.rfsMgr.RefInfo(remoteRef)
	if err != nil {
		return nil, err
	}
	remoteRefCommitID, err := m.rfsMgr.RefCommit(remoteRef)
	if err != nil {
		return nil, err
	}
	remoteInfo, err := m.cfgMgr.RemoteInfo(remoteRefInfo.Remote())
	if err != nil {
		return nil, err
	}

	headCtx := &currentHeadContext{
		headRefInfo:    headRefInfo,
		remoteRefInfo:  remoteRefInfo,
		headCommitID:   headRefCommitID,
		remoteCommitID: remoteRefCommitID,
		server:         remoteInfo.Server(),
		serverPAPPort:  remoteInfo.PAPPort(),
	}
	ledgerID, err := m.rfsMgr.RefLedgerID(headRef)
	if err != nil {
		return nil, err
	}
	headCtx.headRefInfo, err = common.BuildRefInfoFromLedgerID(headRefInfo, ledgerID)
	if err != nil {
		return nil, err
	}

	commit, err := m.rfsMgr.RefCommit(headCtx.Ref())
	if err != nil {
		return nil, err
	}
	headCtx.remoteCommitID = commit

	return headCtx, nil
}

// CurrentHeadCommit gets the current head commit.
func (m *Manager) CurrentHeadCommit(ref string) (*objects.Commit, error) {
	remoteCommitID, err := m.rfsMgr.RefCommit(ref)
	if err != nil {
		return nil, err
	}
	if remoteCommitID == objects.ZeroOID {
		return nil, nil
	}
	remoteCommitObj, err := m.cospMgr.ReadObject(remoteCommitID)
	if err != nil {
		return nil, err
	}
	remoteCommit, err := objects.ConvertObjectToCommit(remoteCommitObj)
	if err != nil {
		return nil, err
	}
	return remoteCommit, nil
}

// CurrentHeadTree gets the current head tree.
func (m *Manager) CurrentHeadTree(ref string) (*objects.Tree, error) {
	commit, err := m.CurrentHeadCommit(ref)
	if err != nil {
		return nil, err
	}
	if commit == nil {
		return nil, nil
	}
	treeObj, err := m.cospMgr.ReadObject(commit.Tree())
	if err != nil {
		return nil, err
	}
	tree, err := objects.ConvertObjectToTree(treeObj)
	if err != nil {
		return nil, err
	}
	return tree, nil
}
