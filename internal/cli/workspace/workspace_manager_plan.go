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
	"time"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azicliwkscosp "github.com/permguard/permguard/internal/cli/workspace/cosp"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlang "github.com/permguard/permguard/pkg/core/languages"
)

// plan generates a plan of changes to apply to the remote ledger based on the differences between the local and remote states.
func (m *WorkspaceManager) plan(currentCodeObsStates []azicliwkscosp.CodeObjectState, remoteCodeObsStates []azicliwkscosp.CodeObjectState) ([]azicliwkscosp.CodeObjectState, error) {
	return m.cospMgr.CalculateCodeObjectsState(currentCodeObsStates, remoteCodeObsStates), nil
}

// buildPlanTree builds the plan tree.
func (m *WorkspaceManager) buildPlanTree(plan []azicliwkscosp.CodeObjectState, absLang azlang.LanguageAbastraction) (*azlangobjs.Tree, *azlangobjs.Object, error) {
	tree, err := azlangobjs.NewTree()
	if err != nil {
		return nil, nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: tree cannot be created")
	}
	for _, planItem := range plan {
		if planItem.State == azicliwkscosp.CodeObjectStateDelete {
			continue
		}
		treeItem, err := azlangobjs.NewTreeEntry(planItem.OType, planItem.OID, planItem.OName, planItem.CodeID, planItem.CodeType, planItem.Language, planItem.LanguageVersion, planItem.LanguageType)
		if err != nil {
			return nil, nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: tree item cannot be created")
		}
		if err := tree.AddEntry(treeItem); err != nil {
			return nil, nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: tree item cannot be added to the tree because of errors in the code files")
		}
	}
	treeObj, err := absLang.CreateTreeObject(tree)
	if err != nil {
		return nil, nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: tree object cannot be created")
	}
	return tree, treeObj, nil
}

// buildPlanCommit builds the plan commit.
func (m *WorkspaceManager) buildPlanCommit(tree string, parentCommitID string, absLang azlang.LanguageAbastraction) (*azlangobjs.Commit, *azlangobjs.Object, error) {
	commit, err := azlangobjs.NewCommit(tree, parentCommitID, "", time.Now(), "", time.Now(), "cli commit")
	if err != nil {
		return nil, nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: commit cannot be created")
	}
	commitObj, err := absLang.CreateCommitObject(commit)
	if err != nil {
		return nil, nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: commit object cannot be created")
	}
	return commit, commitObj, nil
}
