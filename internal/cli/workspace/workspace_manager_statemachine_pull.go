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

// PullResult holds the result of a pull operation.
type PullResult struct {
	LocalCommitID     string
	RemoteCommitID    string
	LocalCommitCount  uint32
	RemoteCommitCount uint32
	Committed         bool
}

// execRemotePull performs a synchronous pull from the remote server.
func (m *Manager) execRemotePull(headCtx *currentHeadContext, out common.PrinterOutFunc) (*PullResult, error) {
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "pull", "Advertising - Initiating request for ledger state.", nil, true)
	}

	papClient, err := m.rmSrvtMgr.NewPAPClientSession(headCtx.Server(), headCtx.ServerPAPPort(), headCtx.Scheme())
	if err != nil {
		return nil, fmt.Errorf("cli: failed to create PAP client: %w", err)
	}
	defer func() { _ = papClient.Close() }()

	localCommitID := headCtx.remoteCommitID

	// Step 1: PullState
	stateResp, err := papClient.PullState(&pap.PullStateRequest{
		ZoneID:        headCtx.ZoneID(),
		LedgerID:      headCtx.LedgerID(),
		RefCommit:     localCommitID,
		RefPrevCommit: localCommitID,
	})
	if err != nil {
		return nil, fmt.Errorf("cli: pull state failed: %w", err)
	}

	remoteCommitID := stateResp.ServerCommit

	if stateResp.IsUpToDate {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "pull", "Already up to date.", nil, true)
		}
		return &PullResult{
			LocalCommitID:     localCommitID,
			RemoteCommitID:    remoteCommitID,
			LocalCommitCount:  0,
			RemoteCommitCount: stateResp.NumberOfCommits,
			Committed:         false,
		}, nil
	}
	if stateResp.HasConflicts {
		return nil, errors.New("cli: conflicts detected in the remote ledger")
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "pull", "Negotiation - Requesting commit list.", nil, true)
	}

	// Step 2: PullNegotiate
	negResp, err := papClient.PullNegotiate(&pap.PullNegotiateRequest{
		ZoneID:         headCtx.ZoneID(),
		LedgerID:       headCtx.LedgerID(),
		LocalCommitID:  localCommitID,
		RemoteCommitID: remoteCommitID,
	})
	if err != nil {
		return nil, fmt.Errorf("cli: pull negotiate failed: %w", err)
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "pull", fmt.Sprintf("Data Exchange - Pulling %d commit(s).", len(negResp.CommitIDs)), nil, true)
	}

	// Step 3: PullObjects for each commit
	localCommitCount := uint32(0)
	for _, commitID := range negResp.CommitIDs {
		objResp, err := papClient.PullObjects(&pap.PullObjectsRequest{
			ZoneID:   headCtx.ZoneID(),
			LedgerID: headCtx.LedgerID(),
			CommitID: commitID,
		})
		if err != nil {
			return nil, fmt.Errorf("cli: pull objects failed for commit %s: %w", commitID, err)
		}
		for _, obj := range objResp.Objects {
			if err := objects.VerifyOID(obj.OID, obj.Content); err != nil {
				return nil, fmt.Errorf("cli: received corrupted object %s: %w", obj.OID, err)
			}
			if err := objects.ValidateObjectSize(obj.Content, objects.DefaultMaxObjectSize); err != nil {
				return nil, fmt.Errorf("cli: received oversized object %s: %w", obj.OID, err)
			}
			_, err = m.cospMgr.SaveObject(obj.OID, obj.Content)
			if err != nil {
				return nil, fmt.Errorf("cli: failed to save object %s: %w", obj.OID, err)
			}
		}
		// Verify commit graph integrity: commit → tree → all blobs must exist.
		if err := m.objMar.VerifyCommitGraphIntegrity(commitID, func(oid string) (*objects.Object, error) {
			return m.cospMgr.ReadObject(oid)
		}); err != nil {
			return nil, fmt.Errorf("cli: graph integrity check failed for commit %s: %w", commitID, err)
		}
		localCommitCount++
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "pull", "Commit - Pull completed successfully.", nil, true)
	}

	return &PullResult{
		LocalCommitID:     localCommitID,
		RemoteCommitID:    remoteCommitID,
		LocalCommitCount:  localCommitCount,
		RemoteCommitCount: stateResp.NumberOfCommits,
		Committed:         true,
	}, nil
}
