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

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"

	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines/packets"
	notpagstatemachines "github.com/permguard/permguard/internal/agents/notp/statemachines"
	notpagpackets "github.com/permguard/permguard/internal/agents/notp/statemachines/packets"
)

// extractMetaData extracts the meta data.
func (s SQLiteCentralStoragePAP) extractMetaData(handlerCtx *notpstatemachines.HandlerContext) (int64, string) {
	accountIDVal, ok := handlerCtx.Get(notpagstatemachines.AccountIDKey)
	if !ok {
		return 0, ""
	}
	accountIDStr, ok := accountIDVal.(string)
	if !ok {
		return 0, ""
	}
	accountID, err := strconv.ParseInt(accountIDStr, 10, 64)
	if err != nil {
		return 0, ""
	}
	repoIDVal, ok := handlerCtx.Get(notpagstatemachines.RepositoryIDKey)
	if !ok {
		return 0, ""
	}
	repoID, ok := repoIDVal.(string)
	if !ok {
		return 0, ""
	}
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
	repo, err := s.readRepoFromHandlerContext(handlerCtx)
	if err != nil {
		return nil, err
	}
	commit := repo.Refs
	hasConflicts := false
	if repo.Refs != azlangobjs.ZeroOID {
		// TODO implement logic to check if there are conflicts
		hasConflicts = false
	}
	packet := &notpagpackets.LocalRefStatePacket{
		RefCommit: commit,
		HasConflicts: hasConflicts,
	}
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		MessageValue: notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue),
		Packetables: []notppackets.Packetable{packet},
	}
	return handlerReturn, nil
}

// OnPushSendNotifyCurrentStateResponse handles the current state response.
func (s SQLiteCentralStoragePAP) OnPushSendNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
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
func (s SQLiteCentralStoragePAP) OnPushHandleExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error){
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	return handlerReturn, nil
}
