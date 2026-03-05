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

	"github.com/permguard/permguard/ztauthstar/pkg/authz/objects"

	notpagpkts "github.com/permguard/permguard/internal/transport/notp/statemachines/packets"
	notppkts "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	statemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	smpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
)

// OnPushSendNotifyCurrentState notifies the current state.
func (m *Manager) OnPushSendNotifyCurrentState(handlerCtx *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Advertising - Initiating ledger state notification.", true)
	}
	handlerCtx.SetValue(CommittedKey, false)
	localCommitObj, _ := getFromHandlerContext[*objects.Object](handlerCtx, LocalCodeCommitObjectKey)
	packet := &notpagpkts.RemoteRefStatePacket{
		RefPrevCommit: wksCtx.ctx.remoteCommitID,
		RefCommit:     localCommitObj.OID(),
	}
	handlerReturn := &statemachines.HostHandlerReturn{
		Packetables: []notppkts.Packetable{packet},
	}
	return handlerReturn, nil
}

// OnPushHandleNotifyCurrentStateResponse handles the current state response.
func (m *Manager) OnPushHandleNotifyCurrentStateResponse(handlerCtx *statemachines.HandlerContext, _ *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Advertising - Processing response to ledger state notification.", true)
	}
	localRefSPacket := &notpagpkts.LocalRefStatePacket{}
	err := notppkts.ConvertPacketable(packets[0], localRefSPacket)
	if err != nil {
		return nil, err
	}
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
	handlerReturn.MessageValue = notppkts.CombineUint32toUint64(smpackets.AcknowledgedValue, smpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPushHandleNegotiationRequest handles the negotiation request.
func (m *Manager) OnPushHandleNegotiationRequest(handlerCtx *statemachines.HandlerContext, _ *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-commit", "Negotiation - Handling negotiation request between local and remote commit", true)
	}
	localCommitObj, _ := getFromHandlerContext[*objects.Object](handlerCtx, LocalCodeCommitObjectKey)
	remoteCommitID, _ := getFromHandlerContext[string](handlerCtx, RemoteCommitIDKey)
	commitIDs := []string{}
	localCommitID := localCommitObj.OID()
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
	handlerCtx.SetValue(DiffCommitIDsKey, commitIDs)
	handlerCtx.SetValue(DiffCommitIDCursorKey, -1)
	handlerReturn := &statemachines.HostHandlerReturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppkts.CombineUint32toUint64(smpackets.AcknowledgedValue, smpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPushSendNegotiationResponse sends the negotiation response.
func (m *Manager) OnPushSendNegotiationResponse(handlerCtx *statemachines.HandlerContext, _ *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Negotiation - Dispatching response to negotiation request.", true)
	}
	handlerReturn := &statemachines.HostHandlerReturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppkts.CombineUint32toUint64(smpackets.AcknowledgedValue, smpackets.UnknownValue)
	return handlerReturn, nil
}

// buildPushPacketablesForCommit builds the push packetables for the tree.
func (m *Manager) buildPushPacketablesForCommit(isCode bool, commitObj *objects.Object) ([]notppkts.Packetable, error) {
	packetable := []notppkts.Packetable{}

	commit, err := objects.ConvertObjectToCommit(commitObj)
	if err != nil {
		return nil, err
	}
	packetCommit := &notpagpkts.ObjectStatePacket{
		OID:     commitObj.OID(),
		OType:   objects.ObjectTypeCommit,
		Content: commitObj.Content(),
	}
	packetable = append(packetable, packetCommit)

	var treeObj *objects.Object
	if isCode {
		treeObj, err = m.cospMgr.ReadCodeSourceObject(commit.Tree())
	} else {
		treeObj, err = m.cospMgr.ReadObject(commit.Tree())
	}
	if err != nil {
		return nil, err
	}
	tree, err := objects.ConvertObjectToTree(treeObj)
	if err != nil {
		return nil, err
	}
	packetTree := &notpagpkts.ObjectStatePacket{
		OID:     treeObj.OID(),
		OType:   objects.ObjectTypeTree,
		Content: treeObj.Content(),
	}
	packetable = append(packetable, packetTree)

	for _, entry := range tree.Entries() {
		oid := entry.OID()
		oType := entry.Type()
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
		packet := &notpagpkts.ObjectStatePacket{
			OID:     oid,
			OType:   oType,
			Content: obj.Content(),
		}
		packetable = append(packetable, packet)
	}
	return packetable, nil
}

// OnPushExchangeDataStream exchanges the data stream.
func (m *Manager) OnPushExchangeDataStream(handlerCtx *statemachines.HandlerContext, _ *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Data Exchange - Handling data exchange.", true)
	}
	handlerReturn := &statemachines.HostHandlerReturn{
		Packetables: packets,
	}
	commitIDs, _ := getFromHandlerContext[[]string](handlerCtx, DiffCommitIDsKey)
	commitIDCursor, _ := getFromHandlerContext[int](handlerCtx, DiffCommitIDCursorKey)
	commitIDCursor++
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
		handlerReturn.MessageValue = notppkts.CombineUint32toUint64(smpackets.AcknowledgedValue, smpackets.ActiveDataStreamValue)
		handlerReturn.HasMore = true
	} else {
		commitObj, _ := getFromHandlerContext[*objects.Object](handlerCtx, LocalCodeCommitObjectKey)
		packetables, err := m.buildPushPacketablesForCommit(true, commitObj)
		if err != nil {
			return nil, err
		}
		handlerReturn.Packetables = packetables
		handlerReturn.MessageValue = notppkts.CombineUint32toUint64(smpackets.AcknowledgedValue, smpackets.CompletedDataStreamValue)
		handlerReturn.HasMore = false
	}
	return handlerReturn, nil
}

// OnPushHandleCommitResponse handles the commit response.
func (m *Manager) OnPushHandleCommitResponse(handlerCtx *statemachines.HandlerContext, _ *smpackets.StatePacket, packets []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-commit", "Commit - Handling commit response.", true)
	}
	_, err := m.cospMgr.CleanCodeSource()
	if err != nil {
		return nil, err
	}
	_, err = m.cospMgr.CleanCode(wksCtx.ctx.Ref())
	if err != nil {
		return nil, err
	}
	_, _ = m.cospMgr.CleanCodeSource()
	handlerReturn := &statemachines.HostHandlerReturn{
		Packetables:  packets,
		MessageValue: notppkts.CombineUint32toUint64(smpackets.AcknowledgedValue, smpackets.UnknownValue),
	}
	handlerCtx.SetValue(CommittedKey, true)
	return handlerReturn, nil
}
