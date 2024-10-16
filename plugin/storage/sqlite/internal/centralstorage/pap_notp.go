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

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azerrors "github.com/permguard/permguard/pkg/core/errors"

	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpagstatemachines "github.com/permguard/permguard/internal/agents/notp/statemachines"
)

const (
	// RemoteCommitIDKey is the remote commit id key.
	RemoteCommitIDKey = "remote-commit-id"
	// TerminationKey is the termination key.
	TerminationKey = "termination"
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

// extractMetaData extracts the meta data.
func (s SQLiteCentralStoragePAP) extractMetaData(ctx *notpstatemachines.HandlerContext) (int64, string) {
	accountIDStr, _ := getFromHandlerContext[string](ctx, notpagstatemachines.AccountIDKey)
	accountID, err := strconv.ParseInt(accountIDStr, 10, 64)
	if err != nil {
		return 0, ""
	}
	repoID, _ := getFromHandlerContext[string](ctx, notpagstatemachines.RepositoryIDKey)
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
