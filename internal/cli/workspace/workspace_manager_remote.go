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
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azlang "github.com/permguard/permguard/pkg/core/languages"
)

// fetchRemote fetches the latest changes from the remote repo.
func (m *WorkspaceManager) fetchRemote() error {
	// TODO: Implement this method
	return nil
}

// GetCurrentHeadCommit gets the current head commit.
func (m *WorkspaceManager) GetCurrentHeadCommit(absLang azlang.LanguageAbastraction, ref string) (*azlangobjs.Commit, error) {
	remoteCommitID, err := m.rfsMgr.GetRefCommit(ref)
	if err != nil {
		return nil, err
	}
	if remoteCommitID == azlangobjs.ZeroOID {
		return nil, nil
	}
	remoteCommitObj, err := m.cospMgr.ReadObject(remoteCommitID)
	if err != nil {
		return nil, err
	}
	remoteCommit, err := absLang.GetCommitObject(remoteCommitObj)
	if err != nil {
		return nil, err
	}
	return remoteCommit, nil
}

// GetCurrentHeadTree gets the current head tree.
func (m *WorkspaceManager) GetCurrentHeadTree(absLang azlang.LanguageAbastraction, ref string) (*azlangobjs.Tree, error) {
	commit, err := m.GetCurrentHeadCommit(absLang, ref)
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
	tree, err := absLang.GetTreeeObject(treeObj)
	if err != nil {
		return nil, err
	}
	return tree, nil
}
