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

	notpagpkts "github.com/permguard/permguard/internal/transport/notp/statemachines/packets"
	notppkts "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	statemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	smpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
)

// OnPullSendRequestCurrentState sends the current state request.
func (m *Manager) OnPullSendRequestCurrentState(handlerCtx *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-pull", "Advertising - Initiating request for ledger state.", true)
	}
	handlerCtx.SetValue(CommittedKey, false)
	packet := &notpagpkts.RemoteRefStatePacket{
		RefPrevCommit: wksCtx.ctx.remoteCommitID,
		RefCommit:     wksCtx.ctx.remoteCommitID,
	}
	handlerReturn := &statemachines.HostHandlerReturn{
		Packetables: []notppkts.Packetable{packet},
	}
	handlerCtx.SetValue(LocalCodeCommitIDKey, wksCtx.ctx.remoteCommitID)
	return handlerReturn, nil
}

// OnPullHandleRequestCurrentStateResponse handles the current state response.
func (m *Manager) OnPullHandleRequestCurrentStateResponse(handlerCtx *statemachines.HandlerContext, _ *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-pull", "Advertising - Processing response for ledger state request.", true)
	}
	localRefSPacket := &notpagpkts.LocalRefStatePacket{}
	err := notppkts.ConvertPacketable(packets[0], localRefSPacket)
	if err != nil {
		return nil, err
	}
	handlerCtx.SetValue(RemoteCommitIDKey, localRefSPacket.RefCommit)
	handlerReturn := &statemachines.HostHandlerReturn{
		Packetables: packets,
	}
	if localRefSPacket.IsUpToDate {
		handlerReturn.Terminate = true
		return handlerReturn, nil
	}
	if localRefSPacket.HasConflicts {
		return nil, errors.New("cli: conflicts detected in the remote ledger")
	}
	handlerCtx.SetValue(RemoteCommitIDKey, localRefSPacket.RefCommit)
	handlerCtx.SetValue(RemoteCommitsCountKey, localRefSPacket.NumberOfCommits)
	handlerCtx.SetValue(LocalCommitsCountKey, uint32(0))
	handlerReturn.MessageValue = notppkts.CombineUint32toUint64(smpackets.AcknowledgedValue, smpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPullSendNegotiationRequest sends the negotiation request.
func (m *Manager) OnPullSendNegotiationRequest(handlerCtx *statemachines.HandlerContext, _ *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-pull", "Negotiation - Sending negotiation request.", true)
	}
	handlerReturn := &statemachines.HostHandlerReturn{
		Packetables:  packets,
		MessageValue: notppkts.CombineUint32toUint64(smpackets.AcknowledgedValue, smpackets.UnknownValue),
	}
	return handlerReturn, nil
}

// OnPullHandleNegotiationResponse handle the negotiation response.
func (m *Manager) OnPullHandleNegotiationResponse(handlerCtx *statemachines.HandlerContext, _ *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-pull", "Negotiation - Processing response to negotiation request.", true)
	}
	handlerReturn := &statemachines.HostHandlerReturn{
		Packetables:  packets,
		MessageValue: notppkts.CombineUint32toUint64(smpackets.AcknowledgedValue, smpackets.UnknownValue),
	}
	return handlerReturn, nil
}

// OnPullHandleExchangeDataStream handles the data exchange.
func (m *Manager) OnPullHandleExchangeDataStream(handlerCtx *statemachines.HandlerContext, statePacket *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-pull", "Data Exchange - Managing data exchange.", true)
	}
	for _, packet := range packets {
		objStatePacket := &notpagpkts.ObjectStatePacket{}
		err := notppkts.ConvertPacketable(packet, objStatePacket)
		if err != nil {
			return nil, err
		}
		_, err = m.cospMgr.SaveObject(objStatePacket.OID, objStatePacket.Content)
		if err != nil {
			return nil, err
		}
	}
	commitsCount, _ := getFromHandlerContext[uint32](handlerCtx, LocalCommitsCountKey)
	commitsCount++
	handlerCtx.SetValue(LocalCommitsCountKey, commitsCount)
	handlerReturn := &statemachines.HostHandlerReturn{
		Packetables:  []notppkts.Packetable{},
		MessageValue: statePacket.MessageValue,
	}
	return handlerReturn, nil
}

// OnPullSendCommit handles the commit response.
func (m *Manager) OnPullSendCommit(handlerCtx *statemachines.HandlerContext, _ *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-commit", "Commit - Sending commit request.", true)
	}
	handlerReturn := &statemachines.HostHandlerReturn{
		Packetables:  packets,
		MessageValue: notppkts.CombineUint32toUint64(smpackets.AcknowledgedValue, smpackets.UnknownValue),
	}
	handlerCtx.SetValue(CommittedKey, true)
	return handlerReturn, nil
}
