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
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azerrors "github.com/permguard/permguard/pkg/core/errors"

	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines/packets"
	notpagpackets "github.com/permguard/permguard/internal/agents/notp/statemachines/packets"
)

const (
	// OutFuncKey represents the apply out func key.
	OutFuncKey = "output-func"
	// LocalCodeTreeObjectKey represents the local code tree object key.
	LocalCodeTreeObjectKey = "local-code-tree-object"
	// LocalCodeCommitKey represents the local code commit key.
	LocalCodeCommitKey = "local-code-commit"
	// LocalCodeCommitObjectKey represents the local code commit object key.
	LocalCodeCommitObjectKey = "local-code-commit-object"
	// RemoteCommitKey represents the remote commit key.
	RemoteCommitKey = "remote-commit"
	// DiffTreeIDsKey represents the diff tree ids key.
	DiffTreeIDsKey = "diff-tree-items"
	// HeadContextKey represents the head context key.
	HeadContextKey = "head-context"
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

// workspaceHandlerContext represents the workspace handler context.
type workspaceHandlerContext struct {
	outFunc func(key string, output string, newLine bool)
	tree    *azlangobjs.Object
	ctx     *currentHeadContext
}

// createWorkspaceHandlerContext creates the workspace handler context.
func createWorkspaceHandlerContext(ctx *notpstatemachines.HandlerContext) *workspaceHandlerContext {
	outfunc, _ := getFromHandlerContext[func(key string, output string, newLine bool)](ctx, OutFuncKey)
	tree, _ := getFromHandlerContext[*azlangobjs.Object](ctx, LocalCodeTreeObjectKey)
	headContext, _ := getFromHandlerContext[*currentHeadContext](ctx, HeadContextKey)
	wksCtx := &workspaceHandlerContext{
		outFunc: outfunc,
		tree:    tree,
		ctx:     headContext,
	}
	return wksCtx
}

// OnPushSendNotifyCurrentState notifies the current state.
func (m *WorkspaceManager) OnPushSendNotifyCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Advertising - Initiating notification dispatch for the current repository state.", true)
	}
	packet := &notpagpackets.RemoteRefStatePacket{
		RefCommit: wksCtx.ctx.commit,
	}
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: []notppackets.Packetable{packet},
	}
	return handlerReturn, nil
}

// OnPushHandleNotifyCurrentStateResponse handles the current state response.
func (m *WorkspaceManager) OnPushHandleNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Advertising - Dispatching response to the current repository state request.", true)
	}
	localRefSPacket := &notpagpackets.LocalRefStatePacket{}
	err := notppackets.ConvertPacketable(packets[0], localRefSPacket)
	if err != nil {
		return nil, err
	}
	if localRefSPacket.HasConflicts {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspace, "workspace: conflicts detected in the remote repository.")
	}
	handlerCtx.Set(RemoteCommitKey, localRefSPacket.RefCommit)
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPushHandleNegotiationRequest handles the negotiation request.
func (m *WorkspaceManager) OnPushHandleNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Negotiation - Managing the negotiation request.", true)
	}
	localCommit, _ := getFromHandlerContext[string](handlerCtx, LocalCodeCommitKey)
	remoteCommit, _ := getFromHandlerContext[string](handlerCtx, RemoteCommitKey)
	treeIDs := []string{}
	if localCommit != remoteCommit {
		//TODO implement logic to get the diff tree items
	}
	handlerCtx.Set(DiffTreeIDsKey, treeIDs)
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPushSendNegotiationResponse sends the negotiation response.
func (m *WorkspaceManager) OnPushSendNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Negotiation - Dispatching response to the active negotiation request.", true)
	}
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// onPushTreeExchangeData exchanges the tree data.
func (m *WorkspaceManager) onPushTreeExchangeData(handlerCtx *notpstatemachines.HandlerContext,treeObj *azlangobjs.Object) error {
	return nil
}

// OnPushExchangeDataStream exchanges the data stream.
func (m *WorkspaceManager) OnPushExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Data Exchabge - Handling data exchange.", true)
	}
	treeIDs, _ := getFromHandlerContext[[]string](handlerCtx, DiffTreeIDsKey)
	for _, treeID := range treeIDs {
		treeObj, err := m.cospMgr.ReadObject(treeID)
		if err != nil {
			return nil, err
		}
		err = m.onPushTreeExchangeData(handlerCtx, treeObj)
		if err != nil {
			return nil, err
		}
	}
	treeObj, _ := getFromHandlerContext[*azlangobjs.Object](handlerCtx, LocalCodeTreeObjectKey)
	err := m.onPushTreeExchangeData(handlerCtx, treeObj)
	if err != nil {
		return nil, err
	}
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.ActiveDataStreamValue)
	handlerReturn.HasMore = false
	return handlerReturn, nil
}
