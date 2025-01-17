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
	azerrors "github.com/permguard/permguard/pkg/core/errors"

	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines/packets"
	notpagpackets "github.com/permguard/permguard/internal/transport/notp/statemachines/packets"
)

// OnPullSendRequestCurrentState sends the current state request.
func (m *WorkspaceManager) OnPullSendRequestCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-pull", "Advertising - Initiating request for ledger state.", true)
	}
	handlerCtx.Set(CommittedKey, false)
	packet := &notpagpackets.RemoteRefStatePacket{
		RefPrevCommit: wksCtx.ctx.remoteCommitID,
		RefCommit:     wksCtx.ctx.remoteCommitID,
	}
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: []notppackets.Packetable{packet},
	}
	handlerCtx.Set(LocalCodeCommitIDKey, wksCtx.ctx.remoteCommitID)
	return handlerReturn, nil
}

// OnPullHandleRequestCurrentStateResponse handles the current state response.
func (m *WorkspaceManager) OnPullHandleRequestCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-pull", "Advertising - Processing response for ledger state request.", true)
	}
	localRefSPacket := &notpagpackets.LocalRefStatePacket{}
	err := notppackets.ConvertPacketable(packets[0], localRefSPacket)
	if err != nil {
		return nil, err
	}
	handlerCtx.Set(RemoteCommitIDKey, localRefSPacket.RefCommit)
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	if localRefSPacket.IsUpToDate {
		handlerReturn.Terminate = true
		return handlerReturn, nil
	}
	if localRefSPacket.HasConflicts {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliWorkspace, "workspace: conflicts detected in the remote ledger.")
	}
	handlerCtx.Set(RemoteCommitIDKey, localRefSPacket.RefCommit)
	handlerCtx.Set(RemoteCommitsCountKey, localRefSPacket.NumberOfCommits)
	handlerCtx.Set(LocalCommitsCountKey, uint32(0))
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPullSendNegotiationRequest sends the negotiation request.
func (m *WorkspaceManager) OnPullSendNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-pull", "Negotiation - Sending negotiation request.", true)
	}
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables:  packets,
		MessageValue: notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue),
	}
	return handlerReturn, nil
}

// OnPullHandleNegotiationResponse handle the negotiation response.
func (m *WorkspaceManager) OnPullHandleNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-pull", "Negotiation - Processing response to negotiation request.", true)
	}
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables:  packets,
		MessageValue: notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue),
	}
	return handlerReturn, nil
}

// OnPullHandleExchangeDataStream handles the data exchange.
func (m *WorkspaceManager) OnPullHandleExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-pull", "Data Exchange - Managing data exchange.", true)
	}
	for _, packet := range packets {
		objStatePacket := &notpagpackets.ObjectStatePacket{}
		err := notppackets.ConvertPacketable(packet, objStatePacket)
		if err != nil {
			return nil, err
		}
		_, err = m.cospMgr.SaveObject(objStatePacket.OID, objStatePacket.Content)
		if err != nil {
			return nil, err
		}
	}
	commitsCount, _ := getFromHandlerContext[uint32](handlerCtx, LocalCommitsCountKey)
	commitsCount = commitsCount + 1
	handlerCtx.Set(LocalCommitsCountKey, commitsCount)
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables:  []notppackets.Packetable{},
		MessageValue: statePacket.MessageValue,
	}
	return handlerReturn, nil
}

// OnPullSendCommit handles the commit response.
func (m *WorkspaceManager) OnPullSendCommit(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-commit", "Commit - Sending commit request.", true)
	}
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables:  packets,
		MessageValue: notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue),
	}
	handlerCtx.Set(CommittedKey, true)
	return handlerReturn, nil
}
