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
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"

	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines/packets"
	notpagpackets "github.com/permguard/permguard/internal/transport/notp/statemachines/packets"
)

// OnPushHandleNotifyCurrentState notifies the current state.
func (s SQLiteCentralStoragePAP) OnPushHandleNotifyCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	if len(packets) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid input packets for notify current state.")
	}
	remoteRefPacket := &notpagpackets.RemoteRefStatePacket{}
	err := notppackets.ConvertPacketable(packets[0], remoteRefPacket)
	if err != nil {
		return nil, err
	}
	if remoteRefPacket.RefCommit == "" || remoteRefPacket.RefPrevCommit == "" {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientParameter, "storage: invalid remote ref state packet.")
	}
	ledger, err := s.readLedgerFromHandlerContext(handlerCtx)
	if err != nil {
		return nil, err
	}
	headCommitID := ledger.Ref
	hasConflicts := false
	isUpToDate := false
	if headCommitID != azlangobjs.ZeroOID && headCommitID != remoteRefPacket.RefPrevCommit {
		objMng, err := azlangobjs.NewObjectManager()
		if err != nil {
			return nil, err
		}
		db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
		if err != nil {
			return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
		}
		hasMatch, history, err := objMng.BuildCommitHistory(headCommitID, remoteRefPacket.RefPrevCommit, false, func(oid string) (*azlangobjs.Object, error) {
			keyValue, errkey := s.sqlRepo.GetKeyValue(db, oid)
			if errkey != nil || keyValue == nil || keyValue.Value == nil {
				return nil, nil
			}
			return azlangobjs.NewObject(keyValue.Value)
		})
		if err != nil {
			return nil, err
		}
		hasConflicts = hasMatch && len(history) > 1
		if headCommitID != azlangobjs.ZeroOID && remoteRefPacket.RefPrevCommit == azlangobjs.ZeroOID {
			hasConflicts = true
		}
		isUpToDate = headCommitID == remoteRefPacket.RefCommit
	}
	packet := &notpagpackets.LocalRefStatePacket{
		RefCommit:    headCommitID,
		HasConflicts: hasConflicts,
		IsUpToDate:   isUpToDate,
	}
	handlerCtx.Set(RemoteCommitIDKey, remoteRefPacket.RefCommit)
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		MessageValue: notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue),
		Packetables:  []notppackets.Packetable{packet},
	}
	handlerCtx.Set(TerminationKey, isUpToDate)
	return handlerReturn, nil
}

// OnPushSendNotifyCurrentStateResponse handles the current state response.
func (s SQLiteCentralStoragePAP) OnPushSendNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	terminate, _ := getFromHandlerContext[bool](handlerCtx, TerminationKey)
	handlerReturn.Terminate = terminate
	return handlerReturn, nil
}

// OnPushSendNegotiationRequest sends the negotiation request.
func (s SQLiteCentralStoragePAP) OnPushSendNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	return handlerReturn, nil
}

// OnPushHandleNegotiationResponse handles the negotiation response.
func (s SQLiteCentralStoragePAP) OnPushHandleNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPushHandleExchangeDataStream exchanges the data stream.
func (s SQLiteCentralStoragePAP) OnPushHandleExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
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
		ledger, err := s.readLedgerFromHandlerContext(handlerCtx)
		if err != nil {
			return nil, err
		}
		remoteCommitID, _ := getFromHandlerContext[string](handlerCtx, RemoteCommitIDKey)
		err = s.sqlRepo.UpdateLedgerRef(tx, ledger.ApplicationID, ledger.LedgerID, ledger.Ref, remoteCommitID)
		if err := tx.Commit(); err != nil {
			return nil, azirepos.WrapSqlite3Error(errorMessageCannotCommitTransaction, err)
		}
	}
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	return handlerReturn, nil
}

// OnPushSendCommit sends the commit.
func (s SQLiteCentralStoragePAP) OnPushSendCommit(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}
