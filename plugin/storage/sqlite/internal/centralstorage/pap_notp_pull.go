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
	notpagpackets "github.com/permguard/permguard/internal/agents/notp/statemachines/packets"
)

// OnPullHandleRequestCurrentState handles the request for the current state.
func (s SQLiteCentralStoragePAP) OnPullHandleRequestCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
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
			return azlangobjs.NewObject(keyValue.Value)
		})
		hasConflicts = hasMatch && len(history) > 1
		if headCommitID == azlangobjs.ZeroOID && remoteRefSPacket.RefPrevCommit != azlangobjs.ZeroOID {
			hasConflicts = true
		}
		isUpToDate = headCommitID == remoteRefSPacket.RefCommit
	}
	packet := &notpagpackets.LocalRefStatePacket{
		RefCommit:    headCommitID,
		HasConflicts: hasConflicts,
		IsUpToDate:   isUpToDate,
	}
	handlerCtx.Set(LocalCommitIDKey, headCommitID)
	handlerCtx.Set(RemoteCommitIDKey, remoteRefSPacket.RefCommit)
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		MessageValue: notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue),
		Packetables:  []notppackets.Packetable{packet},
	}
	handlerCtx.Set(TerminationKey, isUpToDate)
	return handlerReturn, nil
}

// OnPullSendNotifyCurrentStateResponse notifies the current state.
func (s SQLiteCentralStoragePAP) OnPullSendNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPullSendNegotiationRequest sends the negotiation request.
func (s SQLiteCentralStoragePAP) OnPullSendNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	localCommitID, _ := getFromHandlerContext[string](handlerCtx, LocalCommitIDKey)
	remoteCommitID, _ := getFromHandlerContext[string](handlerCtx, RemoteCommitIDKey)
	commitIDs := []string{}
	if localCommitID != remoteCommitID {
		objMng, err := azlangobjs.NewObjectManager()
		if err != nil {
			return nil, err
		}
		db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
		if err != nil {
			return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
		}
		_, history, err := objMng.BuildCommitHistory(localCommitID, remoteCommitID, true, func(oid string) (*azlangobjs.Object, error) {
			return s.readObject(db, oid)
		})
		if err != nil {
			return nil, err
		}
		for _, commit := range history {
			obj, err := objMng.CreateCommitObject(&commit)
			if err != nil {
				return nil, err
			}
			commitIDs = append(commitIDs, obj.GetOID())
		}
	}
	handlerCtx.Set(DiffCommitIDsKey, commitIDs)
	handlerCtx.Set(DiffCommitIDCursorKey, -1)
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPullHandleNegotiationResponse handles the negotiation response.
func (s SQLiteCentralStoragePAP) OnPullHandleNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// buildPushPacketablesForCommit builds the push packetables for the tree.
func (s SQLiteCentralStoragePAP) buildPushPacketablesForCommit(commitID string) ([]notppackets.Packetable, error) {
	objMng, err := azlangobjs.NewObjectManager()
	if err != nil {
		return nil, err
	}
	db, err := s.sqlExec.Connect(s.ctx, s.sqliteConnector)
	if err != nil {
		return nil, azirepos.WrapSqlite3Error(errorMessageCannotConnect, err)
	}
	packetable := []notppackets.Packetable{}

	commitObj, err := s.readObject(db, commitID)
	if err != nil {
		return nil, err
	}
	commit, err := GetObjectForType[azlangobjs.Commit](objMng, commitObj)
	if err != nil {
		return nil, err
	}
	packetCommit := &notpagpackets.ObjectStatePacket{
		OID:     commitObj.GetOID(),
		OType:   azlangobjs.ObjectTypeCommit,
		Content: commitObj.GetContent(),
	}
	packetable = append(packetable, packetCommit)

	treeObj, err := s.readObject(db, commit.GetTree())
	if err != nil {
		return nil, err
	}
	tree, err := GetObjectForType[azlangobjs.Tree](objMng, treeObj)
	if err != nil {
		return nil, err
	}

	packetTree := &notpagpackets.ObjectStatePacket{
		OID:     treeObj.GetOID(),
		OType:   azlangobjs.ObjectTypeTree,
		Content: treeObj.GetContent(),
	}
	packetable = append(packetable, packetTree)

	for _, entry := range tree.GetEntries() {
		oid := entry.GetOID()
		oType := entry.GetType()
		obj, err := s.readObject(db, oid)
		if err != nil {
			return nil, err
		}
		packet := &notpagpackets.ObjectStatePacket{
			OID:     oid,
			OType:   oType,
			Content: obj.GetContent(),
		}
		packetable = append(packetable, packet)
	}
	return packetable, nil
}

// OnPullHandleExchangeDataStream exchanges the data stream.
func (s SQLiteCentralStoragePAP) OnPullHandleExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	commitIDs, _ := getFromHandlerContext[[]string](handlerCtx, DiffCommitIDsKey)
	commitIDCursor, _ := getFromHandlerContext[int](handlerCtx, DiffCommitIDCursorKey)
	commitIDCursor = commitIDCursor + 1
	if commitIDCursor < len(commitIDs) {
		commitID := commitIDs[commitIDCursor]
		packetables, err := s.buildPushPacketablesForCommit(commitID)
		if err != nil {
			return nil, err
		}
		handlerReturn.Packetables = packetables
		if commitIDCursor == len(commitIDs)-1 {
			handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.CompletedDataStreamValue)
		} else {
			handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.ActiveDataStreamValue)
		}
		handlerReturn.HasMore = true
	}
	return handlerReturn, nil
}

// OnPullHandleCommit handles the commit.
func (s SQLiteCentralStoragePAP) OnPullHandleCommit(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}
