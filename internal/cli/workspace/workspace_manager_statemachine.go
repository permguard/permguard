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
	azobjstorage "github.com/permguard/permguard-objstorage/pkg/objects"

	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
)

const (
	// OutFuncKey represents the apply out func key.
	OutFuncKey = "output-func"
	// CommittedKey represents the committed key.
	CommittedKey = "committed"
	// LanguageAbstractionKey represents the language abstraction key.
	LanguageAbstractionKey = "language-abstraction"
	// LocalCodeTreeObjectKey represents the local code tree object key.
	LocalCodeTreeObjectKey = "local-code-tree-object"
	// LocalCodeCommitKey represents the local code commit id key.
	LocalCodeCommitKey = "local-code-commit"
	// LocalCodeCommitObjectKey represents the local code commit object key.
	LocalCodeCommitObjectKey = "local-code-commit-object"
	// LocalCodeCommitIDKey represents the local code commit id key.
	LocalCodeCommitIDKey = "local-code-commit-id"
	// LocalCommitsCountKey represents the local commits count key.
	LocalCommitsCountKey = "local-commits-count"
	// RemoteCommitIDKey represents the remote commit id key.
	RemoteCommitIDKey = "remote-commit-id"
	// RemoteCommitsCountKey represents the remote commits count key.
	RemoteCommitsCountKey = "remote-commits-count"
	// DiffCommitIDsKey represents the diff commit ids key.
	DiffCommitIDsKey = "diff-commit-ids"
	// DiffCommitIDCursorKey represents the diff commit id cursor key.
	DiffCommitIDCursorKey = "diff-commit-id-cursor"
	// HeadContextKey represents the head context key.
	HeadContextKey = "head-context"
)

// getFromHandlerContext gets the value from the handler context.
func getFromRuntimeContext[T any](ctx *notpstatemachines.StateMachineRuntimeContext, key string) (T, bool) {
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
	tree    *azobjstorage.Object
	ctx     *currentHeadContext
}

// createWorkspaceHandlerContext creates the workspace handler context.
func createWorkspaceHandlerContext(ctx *notpstatemachines.HandlerContext) *workspaceHandlerContext {
	outfunc, _ := getFromHandlerContext[func(key string, output string, newLine bool)](ctx, OutFuncKey)
	tree, _ := getFromHandlerContext[*azobjstorage.Object](ctx, LocalCodeTreeObjectKey)
	headContext, _ := getFromHandlerContext[*currentHeadContext](ctx, HeadContextKey)
	wksCtx := &workspaceHandlerContext{
		outFunc: outfunc,
		tree:    tree,
		ctx:     headContext,
	}
	return wksCtx
}
