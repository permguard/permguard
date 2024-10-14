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
	"strconv"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"

	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines/packets"
	notpagstatemachines "github.com/permguard/permguard/internal/agents/notp/statemachines"
	notpagpackets "github.com/permguard/permguard/internal/agents/notp/statemachines/packets"
)

const (
	// RemoteCommitIDKey is the remote commit id key.
	RemoteCommitIDKey = "remote-commit-id"
	// TerminationKey is the termination key.
	TerminationKey = "termination"
)

// getFromHandlerContext gets the value from the handler context.
func getFromHandlerContext[T any](ctx *notpstatemachines.HandlerContext, key string) (T, bool) {
	value, ok := ctx.Get(key)
	if !ok {
		var zero T
		return zero, false
	}
	typedValue, ok := value.(T)
	if !ok {
		var zero T
		return zero, false
	}
	return typedValue, true
}

// extractMetaData extracts the meta data.
func (s SQLiteCentralStoragePAP) extractMetaData(ctx *notpstatemachines.HandlerContext) (int64, string) {
	accountIDStr, _ := getFromHandlerContext[string](ctx, notpagstatemachines.AccountIDKey)
	accountID, err := strconv.ParseInt(accountIDStr, 10, 64)
	if err != nil {
		return 0, ""
	}
	repoID, _ := getFromHandlerContext[string](ctx, notpagstatemachines.RepositoryIDKey)
	return accountID, repoID
}

// readRepoFromHandlerContext reads the repository from the handler context.
func (s SQLiteCentralStoragePAP) readRepoFromHandlerContext(handlerCtx *notpstatemachines.HandlerContext) (*azmodels.Repository, error) {
	accountID, repoID := s.extractMetaData(handlerCtx)
	fields := map[string]any{
		azmodels.FieldRepositoryRepositoryID: repoID,
	}
	repos, err := s.FetchRepositories(1, 1, accountID, fields)
	if err != nil {
		return nil, err
	}
	if len(repos) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: repository not found.")
	}
	return &repos[0], nil
}

// OnPushHandleNotifyCurrentState notifies the current state.
func (s SQLiteCentralStoragePAP) OnPushHandleNotifyCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	if len(packets) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid input packets for notify current state.")
	}
	remoteRefSPacket := &notpagpackets.RemoteRefStatePacket{}
	err := notppackets.ConvertPacketable(packets[0], remoteRefSPacket)
	if err != nil {
		return nil, err
	}
	if remoteRefSPacket.RefCommit == "" || remoteRefSPacket.RefPrevCommit == "" {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid remote ref state packet.")
	}
	repo, err := s.readRepoFromHandlerContext(handlerCtx)
	if err != nil {
		return nil, err
	}
	headCommitID := repo.Refs
	hasConflicts := false
	isUpToDate := false
	if headCommitID != azlangobjs.ZeroOID && headCommitID != remoteRefSPacket.RefPrevCommit {
		objMng, err := azlangobjs.NewObjectManager()
		if err != nil {
			return nil, err
		}
		db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
		if err != nil {
			return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
		}
		hasMatch, history, err := objMng.BuildCommitHistory(headCommitID, remoteRefSPacket.RefPrevCommit, false, func(oid string) (*azlangobjs.Object, error) {
			keyValue, err := s.sqlRepo.GetKeyValue(db, oid)
			if err != nil || keyValue == nil || keyValue.Value == nil {
				return nil, nil
			}
			return azlangobjs.NewObject(keyValue.Value), nil
		})
		hasConflicts = hasMatch && len(history) > 1
		isUpToDate = hasMatch && len(history) == 1
	}
	packet := &notpagpackets.LocalRefStatePacket{
		RefCommit:    headCommitID,
		HasConflicts: hasConflicts,
		IsUpToDate:   isUpToDate,
	}
	handlerCtx.Set(RemoteCommitIDKey, remoteRefSPacket.RefCommit)
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		MessageValue: notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue),
		Packetables:  []notppackets.Packetable{packet},
	}
	handlerCtx.Set(TerminationKey, isUpToDate)
	return handlerReturn, nil
}

// OnPushSendNotifyCurrentStateResponse handles the current state response.
func (s SQLiteCentralStoragePAP) OnPushSendNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	terminate, _ := getFromHandlerContext[bool](handlerCtx, TerminationKey)
	handlerReturn.Terminate = terminate
	return handlerReturn, nil
}

// OnPushSendNegotiationRequest sends the negotiation request.
func (s SQLiteCentralStoragePAP) OnPushSendNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	return handlerReturn, nil
}

// OnPushHandleNegotiationResponse handles the negotiation response.
func (s SQLiteCentralStoragePAP) OnPushHandleNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPushHandleExchangeDataStream exchanges the data stream.
func (s SQLiteCentralStoragePAP) OnPushHandleExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotBeginTransaction, err)
	}
	for _, packet := range packets {
		objStatePacket := &notpagpackets.ObjectStatePacket{}
		err = notppackets.ConvertPacketable(packet, objStatePacket)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
		keyValue := &azirepos.KeyValue{
			Key:   objStatePacket.OID,
			Value: objStatePacket.Content,
		}
		_, err = s.sqlRepo.UpsertKeyValue(tx, keyValue)
		if err != nil {
			tx.Rollback()
			return nil, err
		}
	}
	if statePacket.HasCompletedDataStream() {
		repo, err := s.readRepoFromHandlerContext(handlerCtx)
		if err != nil {
			return nil, err
		}
		remoteCommitID, _ := getFromHandlerContext[string](handlerCtx, RemoteCommitIDKey)
		err = s.sqlRepo.UpdateRepositoryRefs(tx, repo.AccountID, repo.RepositoryID, repo.Refs, remoteCommitID)
		if err := tx.Commit(); err != nil {
			return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
		}
	}
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	return handlerReturn, nil
}
