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

	"github.com/permguard/permguard/internal/cli/workspace/cosp"
	cerrors "github.com/permguard/permguard/pkg/core/errors"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// plan generates a plan of changes to apply to the remote ledger based on the differences between the local and remote states.
func (m *WorkspaceManager) plan(currentCodeObsStates []cosp.CodeObjectState, remoteCodeObsStates []cosp.CodeObjectState) ([]cosp.CodeObjectState, error) {
	return m.cospMgr.CalculateCodeObjectsState(currentCodeObsStates, remoteCodeObsStates), nil
}

// buildPlanTree builds the plan tree.
func (m *WorkspaceManager) buildPlanTree(plan []cosp.CodeObjectState) (*objects.Tree, *objects.Object, error) {
	tree, err := objects.NewTree()
	if err != nil {
		return nil, nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliFileOperation, "tree cannot be created", err)
	}
	for _, planItem := range plan {
		if planItem.State == cosp.CodeObjectStateDelete {
			continue
		}
		treeItem, err := objects.NewTreeEntry(planItem.Partition, planItem.OType, planItem.OID, planItem.OName, planItem.CodeID, planItem.CodeType, planItem.Language, planItem.LanguageVersion, planItem.LanguageType)
		if err != nil {
			return nil, nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliFileOperation, "tree item cannot be created", err)
		}
		if err := tree.AddEntry(treeItem); err != nil {
			return nil, nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliFileOperation, "tree item cannot be added to the tree because of errors in the code files", err)
		}
	}
	treeObj, err := objects.CreateTreeObject(tree)
	if err != nil {
		return nil, nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliFileOperation, "tree object cannot be created", err)
	}
	return tree, treeObj, nil
}

// buildPlanCommit builds the plan commit.
func (m *WorkspaceManager) buildPlanCommit(tree string, parentCommitID string) (*objects.Commit, *objects.Object, error) {
	commit, err := objects.NewCommit(tree, parentCommitID, "", time.Now(), "", time.Now(), "cli commit")
	if err != nil {
		return nil, nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliFileOperation, "commit cannot be created", err)
	}
	commitObj, err := objects.CreateCommitObject(commit)
	if err != nil {
		return nil, nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliFileOperation, "commit object cannot be created", err)
	}
	return commit, commitObj, nil
}
