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

	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"

	notpagpackets "github.com/permguard/permguard/internal/transport/notp/statemachines/packets"
	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
)

// OnPushSendNotifyCurrentState notifies the current state.
func (m *WorkspaceManager) OnPushSendNotifyCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Advertising - Initiating ledger state notification.", true)
	}
	handlerCtx.Set(CommittedKey, false)
	localCommitObj, _ := getFromHandlerContext[*objects.Object](handlerCtx, LocalCodeCommitObjectKey)
	packet := &notpagpackets.RemoteRefStatePacket{
		RefPrevCommit: wksCtx.ctx.remoteCommitID,
		RefCommit:     localCommitObj.GetOID(),
	}
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: []notppackets.Packetable{packet},
	}
	return handlerReturn, nil
}

// OnPushHandleNotifyCurrentStateResponse handles the current state response.
func (m *WorkspaceManager) OnPushHandleNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Advertising - Processing response to ledger state notification.", true)
	}
	localRefSPacket := &notpagpackets.LocalRefStatePacket{}
	err := notppackets.ConvertPacketable(packets[0], localRefSPacket)
	if err != nil {
		return nil, err
	}
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	if localRefSPacket.IsUpToDate {
		handlerReturn.Terminate = true
		return handlerReturn, nil
	}
	if localRefSPacket.HasConflicts {
		return nil, errors.New("cli: conflicts detected in the remote ledger")
	}
	handlerCtx.Set(RemoteCommitIDKey, localRefSPacket.RefCommit)
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPushHandleNegotiationRequest handles the negotiation request.
func (m *WorkspaceManager) OnPushHandleNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-commit", "Negotiation - Handling negotiation request between local and remote commit", true)
	}
	localCommitObj, _ := getFromHandlerContext[*objects.Object](handlerCtx, LocalCodeCommitObjectKey)
	remoteCommitID, _ := getFromHandlerContext[string](handlerCtx, RemoteCommitIDKey)
	commitIDs := []string{}
	localCommitID := localCommitObj.GetOID()
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

// OnPushSendNegotiationResponse sends the negotiation response.
func (m *WorkspaceManager) OnPushSendNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Negotiation - Dispatching response to negotiation request.", true)
	}
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// buildPushPacketablesForCommit builds the push packetables for the tree.
func (m *WorkspaceManager) buildPushPacketablesForCommit(isCode bool, commitObj *objects.Object) ([]notppackets.Packetable, error) {
	packetable := []notppackets.Packetable{}

	commit, err := objects.ConvertObjectToCommit(commitObj)
	if err != nil {
		return nil, err
	}
	packetCommit := &notpagpackets.ObjectStatePacket{
		OID:     commitObj.GetOID(),
		OType:   objects.ObjectTypeCommit,
		Content: commitObj.GetContent(),
	}
	packetable = append(packetable, packetCommit)

	var treeObj *objects.Object
	if isCode {
		treeObj, err = m.cospMgr.ReadCodeSourceObject(commit.GetTree())
	} else {
		treeObj, err = m.cospMgr.ReadObject(commit.GetTree())
	}
	if err != nil {
		return nil, err
	}
	tree, err := objects.ConvertObjectToTree(treeObj)
	if err != nil {
		return nil, err
	}
	packetTree := &notpagpackets.ObjectStatePacket{
		OID:     treeObj.GetOID(),
		OType:   objects.ObjectTypeTree,
		Content: treeObj.GetContent(),
	}
	packetable = append(packetable, packetTree)

	for _, entry := range tree.GetEntries() {
		oid := entry.GetOID()
		oType := entry.GetType()
		var obj *objects.Object
		var err error
		if isCode {
			obj, err = m.cospMgr.ReadCodeSourceObject(oid)
		} else {
			obj, err = m.cospMgr.ReadObject(oid)
		}
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

// OnPushExchangeDataStream exchanges the data stream.
func (m *WorkspaceManager) OnPushExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Data Exchange - Handling data exchange.", true)
	}
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables: packets,
	}
	commitIDs, _ := getFromHandlerContext[[]string](handlerCtx, DiffCommitIDsKey)
	commitIDCursor, _ := getFromHandlerContext[int](handlerCtx, DiffCommitIDCursorKey)
	commitIDCursor = commitIDCursor + 1
	if commitIDCursor < len(commitIDs) {
		commitID := commitIDs[commitIDCursor]
		commitObj, err := m.cospMgr.ReadObject(commitID)
		if err != nil {
			return nil, err
		}
		packetables, err := m.buildPushPacketablesForCommit(false, commitObj)
		if err != nil {
			return nil, err
		}
		handlerReturn.Packetables = packetables
		handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.ActiveDataStreamValue)
		handlerReturn.HasMore = true
	} else {
		commitObj, _ := getFromHandlerContext[*objects.Object](handlerCtx, LocalCodeCommitObjectKey)
		packetables, err := m.buildPushPacketablesForCommit(true, commitObj)
		if err != nil {
			return nil, err
		}
		handlerReturn.Packetables = packetables
		handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.CompletedDataStreamValue)
		handlerReturn.HasMore = false
	}
	return handlerReturn, nil
}

// OnPushHandleCommitResponse handles the commit response.
func (m *WorkspaceManager) OnPushHandleCommitResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-commit", "Commit - Handling commit response.", true)
	}
	_, err := m.cospMgr.CleanCodeSource()
	if err != nil {
		return nil, err
	}
	_, err = m.cospMgr.CleanCode(wksCtx.ctx.GetRef())
	if err != nil {
		return nil, err
	}
	m.cospMgr.CleanCodeSource()
	handlerReturn := &notpstatemachines.HostHandlerReturn{
		Packetables:  packets,
		MessageValue: notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue),
	}
	handlerCtx.Set(CommittedKey, true)
	return handlerReturn, nil
}
