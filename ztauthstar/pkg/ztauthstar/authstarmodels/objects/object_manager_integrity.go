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

package objects

import (
	"fmt"
)

// VerifyCommitGraphIntegrity verifies that all objects referenced by a commit exist and are valid.
// It checks: commit → tree → all blob entries.
func (m *ObjectManager) VerifyCommitGraphIntegrity(commitOID string, objFunc func(string) (*Object, error)) error {
	commitObj, err := objFunc(commitOID)
	if err != nil {
		return fmt.Errorf("objects: failed to read commit %s: %w", commitOID, err)
	}
	if commitObj == nil {
		return fmt.Errorf("objects: commit %s not found", commitOID)
	}
	commitInfo, err := m.ObjectInfo(commitObj)
	if err != nil {
		return fmt.Errorf("objects: failed to parse commit %s: %w", commitOID, err)
	}
	commit, ok := commitInfo.Instance().(*Commit)
	if !ok {
		return fmt.Errorf("objects: object %s is not a commit", commitOID)
	}

	treeOID := commit.Tree()
	treeObj, err := objFunc(treeOID)
	if err != nil {
		return fmt.Errorf("objects: failed to read tree %s referenced by commit %s: %w", treeOID, commitOID, err)
	}
	if treeObj == nil {
		return fmt.Errorf("objects: tree %s referenced by commit %s not found", treeOID, commitOID)
	}
	treeInfo, err := m.ObjectInfo(treeObj)
	if err != nil {
		return fmt.Errorf("objects: failed to parse tree %s: %w", treeOID, err)
	}
	tree, ok := treeInfo.Instance().(*Tree)
	if !ok {
		return fmt.Errorf("objects: object %s is not a tree", treeOID)
	}

	for _, entry := range tree.Entries() {
		blobOID := entry.OID()
		blobObj, err := objFunc(blobOID)
		if err != nil {
			return fmt.Errorf("objects: failed to read blob %s referenced by tree %s: %w", blobOID, treeOID, err)
		}
		if blobObj == nil {
			return fmt.Errorf("objects: blob %s referenced by tree %s not found", blobOID, treeOID)
		}
	}
	return nil
}
