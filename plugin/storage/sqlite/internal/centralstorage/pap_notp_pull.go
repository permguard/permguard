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

package centralstorage

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/agents/telemetry"
	"github.com/permguard/permguard/pkg/transport/models/pap"
	azrepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// PullState handles the pull state step.
func (s SQLiteCentralStoragePAP) PullState(ctx context.Context, req *pap.PullStateRequest) (_ *pap.PullStateResponse, retErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.PullState")
	defer span.End()
	start := time.Now()
	defer func() {
		st := telemetry.StatusFromErr(retErr)
		telemetry.PullTotal.Add(ctx, 1, telemetry.StatusAttr(st))
		telemetry.PullDuration.Record(ctx, telemetry.ElapsedSeconds(start), telemetry.OpAttr("state"), telemetry.StatusAttr(st))
	}()
	if req == nil {
		return nil, fmt.Errorf("storage: nil request: %w", azstorage.ErrInvalidInput)
	}
	if req.ZoneID <= 0 {
		return nil, fmt.Errorf("storage: invalid zone id: %w", azstorage.ErrInvalidInput)
	}
	if req.RefCommit == "" || req.RefPrevCommit == "" {
		return nil, fmt.Errorf("storage: invalid ref commit: %w", azstorage.ErrInvalidInput)
	}
	ledger, err := s.readLedger(ctx, req.ZoneID, req.LedgerID)
	if err != nil {
		return nil, err
	}
	headCommitID := ledger.Ref
	hasConflicts := false
	isUpToDate := false
	objMng, err := objects.NewObjectManager()
	if err != nil {
		return nil, err
	}
	if headCommitID != objects.ZeroOID && headCommitID != req.RefPrevCommit {
		db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
		if err != nil {
			return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
		}
		hasMatch, history, err := objMng.BuildCommitHistory(req.RefPrevCommit, headCommitID, false, func(oid string) (*objects.Object, error) {
			keyValue, errK := s.sqlRepo.KeyValue(ctx, db, req.ZoneID, oid)
			if errK != nil || keyValue == nil || keyValue.Value == nil {
				return nil, nil
			}
			return objects.NewObject(keyValue.Value)
		})
		if err != nil {
			return nil, fmt.Errorf("storage: failed to build commit history: %w", err)
		}
		hasConflicts = hasMatch && len(history) > 1
		if headCommitID == objects.ZeroOID && req.RefPrevCommit != objects.ZeroOID {
			hasConflicts = true
		}
		isUpToDate = headCommitID == req.RefCommit
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	_, commits, err := objMng.BuildCommitHistory(headCommitID, req.RefCommit, true, func(oid string) (*objects.Object, error) {
		return s.readObject(ctx, db, req.ZoneID, oid)
	})
	if err != nil {
		return nil, err
	}
	telemetry.PullCommitsCount.Record(ctx, int64(len(commits)))
	span.SetAttributes(attribute.Int("commits_count", len(commits)), attribute.Bool("has_conflicts", hasConflicts))
	return &pap.PullStateResponse{
		ServerCommit:    headCommitID,
		NumberOfCommits: uint32(len(commits)),
		HasConflicts:    hasConflicts,
		IsUpToDate:      isUpToDate,
	}, nil
}

// PullNegotiate handles the pull negotiate step.
func (s SQLiteCentralStoragePAP) PullNegotiate(ctx context.Context, req *pap.PullNegotiateRequest) (_ *pap.PullNegotiateResponse, retErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.PullNegotiate")
	defer span.End()
	start := time.Now()
	defer func() {
		st := telemetry.StatusFromErr(retErr)
		telemetry.PullNegotiateTotal.Add(ctx, 1, telemetry.StatusAttr(st))
		telemetry.PullDuration.Record(ctx, telemetry.ElapsedSeconds(start), telemetry.OpAttr("negotiate"), telemetry.StatusAttr(st))
	}()
	if req == nil {
		return nil, fmt.Errorf("storage: nil request: %w", azstorage.ErrInvalidInput)
	}
	if req.ZoneID <= 0 {
		return nil, fmt.Errorf("storage: invalid zone id: %w", azstorage.ErrInvalidInput)
	}
	commitIDs := []string{}
	if req.LocalCommitID != req.RemoteCommitID {
		objMng, err := objects.NewObjectManager()
		if err != nil {
			return nil, err
		}
		db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
		if err != nil {
			return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
		}
		_, history, err := objMng.BuildCommitHistory(req.RemoteCommitID, req.LocalCommitID, true, func(oid string) (*objects.Object, error) {
			return s.readObject(ctx, db, req.ZoneID, oid)
		})
		if err != nil {
			return nil, err
		}
		for _, commit := range history {
			obj, err := objMng.CreateCommitObject(&commit)
			if err != nil {
				return nil, err
			}
			commitIDs = append(commitIDs, obj.OID())
		}
	}
	span.SetAttributes(attribute.Int("commits_count", len(commitIDs)))
	return &pap.PullNegotiateResponse{
		CommitIDs: commitIDs,
	}, nil
}

// collectObjectsForCommit collects all objects for a given commit.
func (s SQLiteCentralStoragePAP) collectObjectsForCommit(ctx context.Context, zoneID int64, commitID string) ([]pap.ObjectState, error) {
	objMng, err := objects.NewObjectManager()
	if err != nil {
		return nil, err
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azrepos.WrapSqliteError(errorMessageCannotConnect, err)
	}
	result := []pap.ObjectState{}

	commitObj, err := s.readObject(ctx, db, zoneID, commitID)
	if err != nil {
		return nil, err
	}
	commit, err := GetObjectForType[objects.Commit](objMng, commitObj)
	if err != nil {
		return nil, err
	}
	result = append(result, pap.ObjectState{
		OID:     commitObj.OID(),
		OType:   objects.ObjectTypeCommit,
		Content: commitObj.Content(),
	})

	// Include manifest blob if present
	manifestOID := commit.Manifest().String()
	if manifestOID != "" && manifestOID != objects.ZeroOID {
		manifestObj, err := s.readObject(ctx, db, zoneID, manifestOID)
		if err != nil {
			return nil, err
		}
		result = append(result, pap.ObjectState{
			OID:     manifestObj.OID(),
			OType:   objects.ObjectTypeBlob,
			Content: manifestObj.Content(),
		})
	}

	// Include all profile trees and their blob entries
	for _, profile := range commit.Profiles() {
		treeObj, err := s.readObject(ctx, db, zoneID, profile.Tree().String())
		if err != nil {
			return nil, err
		}
		tree, err := GetObjectForType[objects.Tree](objMng, treeObj)
		if err != nil {
			return nil, err
		}
		result = append(result, pap.ObjectState{
			OID:     treeObj.OID(),
			OType:   objects.ObjectTypeTree,
			Content: treeObj.Content(),
		})

		for _, entry := range tree.Entries() {
			obj, err := s.readObject(ctx, db, zoneID, entry.OID())
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

// PullObjects handles the pull objects step.
func (s SQLiteCentralStoragePAP) PullObjects(ctx context.Context, req *pap.PullObjectsRequest) (_ *pap.PullObjectsResponse, retErr error) {
	ctx, span := telemetry.Tracer().Start(ctx, "storage.PullObjects")
	defer span.End()
	start := time.Now()
	defer func() {
		st := telemetry.StatusFromErr(retErr)
		telemetry.PullDuration.Record(ctx, telemetry.ElapsedSeconds(start), telemetry.OpAttr("objects"), telemetry.StatusAttr(st))
	}()
	if req == nil {
		return nil, fmt.Errorf("storage: nil request: %w", azstorage.ErrInvalidInput)
	}
	if req.ZoneID <= 0 {
		return nil, fmt.Errorf("storage: invalid zone id: %w", azstorage.ErrInvalidInput)
	}
	objs, err := s.collectObjectsForCommit(ctx, req.ZoneID, req.CommitID)
	if err != nil {
		return nil, err
	}
	// Validate transfer rate limits for response.
	var totalSize int64
	for _, obj := range objs {
		totalSize += int64(len(obj.Content))
	}
	if err := objects.ValidateTransferLimits(len(objs), totalSize, 0, 0); err != nil {
		return nil, fmt.Errorf("storage: response exceeds transfer limits: %w", err)
	}
	telemetry.PullObjectsCount.Record(ctx, int64(len(objs)))
	span.SetAttributes(attribute.Int("objects_count", len(objs)))
	return &pap.PullObjectsResponse{
		Objects: objs,
	}, nil
}
