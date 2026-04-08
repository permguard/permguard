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
	"time"

	"github.com/permguard/permguard/internal/cli/workspace/cosp"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// plan generates a plan of changes to apply to the remote ledger based on the differences between the local and remote states.
func (m *Manager) plan(currentCodeObsStates []cosp.CodeObjectState, remoteCodeObsStates []cosp.CodeObjectState) []cosp.CodeObjectState {
	return m.cospMgr.CalculateCodeObjectsState(currentCodeObsStates, remoteCodeObsStates)
}

// buildPlanTrees builds one tree per partition from the plan and returns commit profiles.
func (m *Manager) buildPlanTrees(plan []cosp.CodeObjectState) ([]objects.CommitProfile, error) {
	// Group plan items by partition
	partitionItems := map[string][]cosp.CodeObjectState{}
	for _, planItem := range plan {
		if planItem.State == cosp.CodeObjectStateDelete {
			continue
		}
		if planItem.DataType == objects.TreeDataTypeManifest {
			continue
		}
		partitionItems[planItem.Partition] = append(partitionItems[planItem.Partition], planItem)
	}

	var profiles []objects.CommitProfile
	for partition, items := range partitionItems {
		tree, err := objects.NewTree(partition)
		if err != nil {
			return nil, errors.Join(errors.New("cli: tree cannot be created"), err)
		}
		for _, planItem := range items {
			treeItem, err := objects.NewTreeEntry(planItem.OType, planItem.OID, planItem.OName, planItem.DataType, map[string]any{
				objects.MetaKeyCodeID:            planItem.CodeID,
				objects.MetaKeyCodeTypeID:        planItem.CodeTypeID,
				objects.MetaKeyLanguageID:        planItem.LanguageID,
				objects.MetaKeyLanguageVersionID: planItem.LanguageVersionID,
				objects.MetaKeyLanguageTypeID:    planItem.LanguageTypeID,
			})
			if err != nil {
				return nil, errors.Join(errors.New("cli: tree item cannot be created"), err)
			}
			if err = tree.AddEntry(treeItem); err != nil {
				return nil, errors.Join(errors.New("cli: tree item cannot be added to the tree because of errors in the code files"), err)
			}
		}
		treeObj, err := objects.CreateTreeObject(tree)
		if err != nil {
			return nil, errors.Join(errors.New("cli: tree object cannot be created"), err)
		}
		if _, err := m.cospMgr.SaveCodeSourceObject(treeObj.OID(), treeObj.Content()); err != nil {
			return nil, err
		}
		profileKey := "default" + partition
		cp, err := objects.NewCommitProfile(profileKey, objects.CID(treeObj.OID()))
		if err != nil {
			return nil, errors.Join(errors.New("cli: commit profile cannot be created"), err)
		}
		profiles = append(profiles, *cp)
	}
	return profiles, nil
}

// buildPlanCommit builds the plan commit.
// predecessorCommitID is the string from the ref system; ZeroOID and empty string both mean root commit.
func (m *Manager) buildPlanCommit(profiles []objects.CommitProfile, manifest string, predecessorCommitID string) (*objects.Commit, *objects.Object, error) {
	predecessor := objects.NewNullableString(nil)
	if predecessorCommitID != "" && predecessorCommitID != objects.ZeroOID {
		predecessor = objects.NewNullableString(&predecessorCommitID)
	}
	commit, err := objects.NewCommit(profiles, objects.CID(manifest), predecessor, "", time.Now(), "", time.Now(), "")
	if err != nil {
		return nil, nil, errors.Join(errors.New("cli: commit cannot be created"), err)
	}
	commitObj, err := objects.CreateCommitObject(commit)
	if err != nil {
		return nil, nil, errors.Join(errors.New("cli: commit object cannot be created"), err)
	}
	return commit, commitObj, nil
}
