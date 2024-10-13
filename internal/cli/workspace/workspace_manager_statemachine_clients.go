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
	azlang "github.com/permguard/permguard/pkg/core/languages"

	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines/packets"
	notpagpackets "github.com/permguard/permguard/internal/agents/notp/statemachines/packets"
)

const (
	// OutFuncKey represents the apply out func key.
	OutFuncKey = "output-func"
	// LanguageAbstractionKey represents the language abstraction key.
	LanguageAbstractionKey = "language-abstraction"
	// LocalCodeTreeObjectKey represents the local code tree object key.
	LocalCodeTreeObjectKey = "local-code-tree-object"
	// LocalCodeCommitKey represents the local code commit id key.
	LocalCodeCommitKey = "local-code-commit"
	// LocalCodeCommitObjectKey represents the local code commit object key.
	LocalCodeCommitObjectKey = "local-code-commit-object"
	// RemoteCommitIDKey represents the remote commit id key.
	RemoteCommitIDKey = "remote-commit-id"
	// DiffCommitIDsKey represents the diff commit ids key.
	DiffCommitIDsKey = "diff-commit-ids"
	// DiffCommitIDCursorKey represents the diff commit id cursor key.
	DiffCommitIDCursorKey = "diff-commit-id-cursor"
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
		RefCommit: wksCtx.ctx.commitID,
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
	handlerCtx.Set(RemoteCommitIDKey, localRefSPacket.RefCommit)
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	return handlerReturn, nil
}

// OnPushHandleNegotiationRequest handles the negotiation request.
func (m *WorkspaceManager) OnPushHandleNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	if m.ctx.IsVerboseTerminalOutput() {
	}
	absLang, _ := getFromHandlerContext[azlang.LanguageAbastraction](handlerCtx, LanguageAbstractionKey)
	localCommitObj, _ := getFromHandlerContext[*azlangobjs.Object](handlerCtx, LocalCodeCommitObjectKey)
	remoteCommitID, _ := getFromHandlerContext[string](handlerCtx, RemoteCommitIDKey)
	commitIDs := []string{}
	localCommitID := localCommitObj.GetOID()
	if localCommitID!= remoteCommitID {
		objMng, err := azlangobjs.NewObjectManager()
		if err != nil {
			return nil, err
		}
		_, history, err := objMng.BuildCommitHistory(localCommitID, remoteCommitID, true, func(oid string) (*azlangobjs.Object, error) {
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
			obj, err := absLang.CreateCommitObject(&commit)
			if err != nil {
				return nil, err
			}
			commitIDs = append(commitIDs, obj.GetOID())
		}
	}
	handlerCtx.Set(DiffCommitIDsKey, commitIDs)
	handlerCtx.Set(DiffCommitIDCursorKey, -1)
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

// buildPacketablesForCommit builds the packetables for the tree.
func (m *WorkspaceManager) buildPacketablesForCommit(handlerCtx *notpstatemachines.HandlerContext, isCode bool, commitObj *azlangobjs.Object) ([]notppackets.Packetable, error) {
	absLang, _ := getFromHandlerContext[azlang.LanguageAbastraction](handlerCtx, LanguageAbstractionKey)
	packetable := []notppackets.Packetable{}

	commit, err := absLang.GetCommitObject(commitObj)
	if err != nil {
		return nil, err
	}
	packetCommit := &notpagpackets.ObjectStatePacket{
		OID:     commitObj.GetOID(),
		OType:   azlangobjs.ObjectTypeCommit,
		Content: commitObj.GetContent(),
	}
	packetable = append(packetable, packetCommit)

	var treeObj *azlangobjs.Object
	if isCode {
		treeObj, err = m.cospMgr.ReadCodeSourceObject(commit.GetTree())
	} else {
		treeObj, err = m.cospMgr.ReadObject(commit.GetTree())
	}
	if err != nil {
		return nil, err
	}
	tree, err := absLang.GetTreeeObject(treeObj)
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
		var obj *azlangobjs.Object
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
func (m *WorkspaceManager) OnPushExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	wksCtx := createWorkspaceHandlerContext(handlerCtx)
	if m.ctx.IsVerboseTerminalOutput() {
		wksCtx.outFunc("notp-push", "Data Exchabge - Handling data exchange.", true)
	}
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
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
		packetables, err := m.buildPacketablesForCommit(handlerCtx, false, commitObj)
		if err != nil {
			return nil, err
		}
		handlerReturn.Packetables = packetables
		handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.ActiveDataStreamValue)
		handlerReturn.HasMore = true
	} else {
		commitObj, _ := getFromHandlerContext[*azlangobjs.Object](handlerCtx, LocalCodeCommitObjectKey)
		packetables, err := m.buildPacketablesForCommit(handlerCtx, true, commitObj)
		if err != nil {
			return nil, err
		}
		handlerReturn.Packetables = packetables
		handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.CompletedDataStreamValue)
		handlerReturn.HasMore = false
	}
	return handlerReturn, nil
}
