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
	"fmt"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/transport/models/pap"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// PushResult holds the result of a push operation.
type PushResult struct {
	Committed      bool
	RemoteCommitID string
}

// collectObjectsForCommit collects all objects (commit, tree, blobs) for a given commit from local storage.
func (m *Manager) collectObjectsForCommit(isCode bool, commitObj *objects.Object) ([]pap.ObjectState, error) {
	commit, err := objects.ConvertObjectToCommit(commitObj)
	if err != nil {
		return nil, err
	}
	result := []pap.ObjectState{{
		OID:     commitObj.OID(),
		OType:   objects.ObjectTypeCommit,
		Content: commitObj.Content(),
	}}

	// Include manifest blob if present
	manifestOID := commit.Manifest().String()
	if manifestOID != "" && manifestOID != objects.ZeroOID {
		var manifestObj *objects.Object
		if isCode {
			manifestObj, err = m.cospMgr.ReadCodeSourceObject(manifestOID)
		} else {
			manifestObj, err = m.cospMgr.ReadObject(manifestOID)
		}
		if err != nil {
			return nil, err
		}
		result = append(result, pap.ObjectState{
			OID:     manifestObj.OID(),
			OType:   objects.ObjectTypeBlob,
			Content: manifestObj.Content(),
		})
	}

	// Collect all profile trees and their blob entries
	for _, profile := range commit.Profiles() {
		var treeObj *objects.Object
		if isCode {
			treeObj, err = m.cospMgr.ReadCodeSourceObject(profile.Tree().String())
		} else {
			treeObj, err = m.cospMgr.ReadObject(profile.Tree().String())
		}
		if err != nil {
			return nil, err
		}
		tree, err := objects.ConvertObjectToTree(treeObj)
		if err != nil {
			return nil, err
		}
		result = append(result, pap.ObjectState{
			OID:     treeObj.OID(),
			OType:   objects.ObjectTypeTree,
			Content: treeObj.Content(),
		})

		for _, entry := range tree.Entries() {
			var obj *objects.Object
			if isCode {
				obj, err = m.cospMgr.ReadCodeSourceObject(entry.OID())
			} else {
				obj, err = m.cospMgr.ReadObject(entry.OID())
			}
			if err != nil {
				return nil, err
			}
			result = append(result, pap.ObjectState{
				OID:     entry.OID(),
				OType:   entry.OType(),
				Content: obj.Content(),
			})
		}
	}
	return result, nil
}

// execPush performs a synchronous push to the remote server.
func (m *Manager) execPush(headCtx *currentHeadContext, commitObj *objects.Object, out common.PrinterOutFunc) (*PushResult, error) {
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "push", "Advertising - Initiating ledger state notification.", nil, true)
	}

	papClient, err := m.rmSrvtMgr.NewPAPClientSession(headCtx.Server(), headCtx.ServerPAPPort(), headCtx.Scheme())
	if err != nil {
		return nil, fmt.Errorf("cli: failed to create PAP client: %w", err)
	}
	defer func() { _ = papClient.Close() }()

	// Step 1: PushAdvertise
	advResp, err := papClient.PushAdvertise(&pap.PushAdvertiseRequest{
		ZoneID:        headCtx.ZoneID(),
		LedgerID:      headCtx.LedgerID(),
		RefCommit:     commitObj.OID(),
		RefPrevCommit: headCtx.remoteCommitID,
	})
	if err != nil {
		return nil, fmt.Errorf("cli: push advertise failed: %w", err)
	}

	if advResp.IsUpToDate {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "push", "Remote is already up to date.", nil, true)
		}
		return &PushResult{Committed: false, RemoteCommitID: advResp.ServerCommit}, nil
	}
	if advResp.HasConflicts {
		return nil, errors.New("cli: remote ledger has diverged, run 'pull' to sync your workspace then retry")
	}
	txid := advResp.TxID
	remoteCommitID := advResp.ServerCommit

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "push", "Negotiation - Computing diff commits.", nil, true)
	}

	// Step 2: Build diff commit list locally
	localCommitID := commitObj.OID()
	commitIDs := []string{}
	if localCommitID != remoteCommitID {
		objMng, err := objects.NewObjectManager()
		if err != nil {
			return nil, err
		}
		_, history, err := objMng.BuildCommitHistory(localCommitID, remoteCommitID, true, func(oid string) (*objects.Object, error) {
			obj, _ := m.cospMgr.ReadCodeSourceObject(oid)
			if obj == nil {
				obj, _ = m.cospMgr.ReadObject(oid)
			}
			return obj, nil
		})
		if err != nil {
			return nil, err
		}
		for _, commit := range history {
			obj, err := objects.CreateCommitObject(&commit)
			if err != nil {
				return nil, err
			}
			commitIDs = append(commitIDs, obj.OID())
		}
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "push", fmt.Sprintf("Data Exchange - Transferring %d commit(s).", len(commitIDs)+1), nil, true)
	}

	// Step 3: Transfer diff commits (non-code objects from history)
	for _, cid := range commitIDs {
		cidObj, err := m.cospMgr.ReadObject(cid)
		if err != nil {
			return nil, err
		}
		objs, err := m.collectObjectsForCommit(false, cidObj)
		if err != nil {
			return nil, err
		}
		_, err = papClient.PushTransfer(&pap.PushTransferRequest{
			TxID:     txid,
			ZoneID:   headCtx.ZoneID(),
			LedgerID: headCtx.LedgerID(),
			Objects:  objs,
			IsLast:   false,
		})
		if err != nil {
			return nil, fmt.Errorf("cli: push transfer failed: %w", err)
		}
	}

	// Step 4: Transfer the current (code) commit as last
	codeObjs, err := m.collectObjectsForCommit(true, commitObj)
	if err != nil {
		return nil, err
	}
	transferResp, err := papClient.PushTransfer(&pap.PushTransferRequest{
		TxID:                 txid,
		ZoneID:               headCtx.ZoneID(),
		LedgerID:             headCtx.LedgerID(),
		Objects:              codeObjs,
		IsLast:               true,
		RemoteCommitID:       commitObj.OID(),
		ExpectedServerCommit: remoteCommitID,
	})
	if err != nil {
		return nil, fmt.Errorf("cli: push transfer (final) failed: %w", err)
	}

	if !transferResp.Committed {
		return nil, errors.New("cli: server did not commit the push")
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "push", "Commit - Push committed successfully.", nil, true)
	}

	// Clean up local code source
	_, err = m.cospMgr.CleanCodeSource()
	if err != nil {
		return nil, err
	}
	_, err = m.cospMgr.CleanCode(headCtx.Ref())
	if err != nil {
		return nil, err
	}

	return &PushResult{Committed: true, RemoteCommitID: commitObj.OID()}, nil
}
