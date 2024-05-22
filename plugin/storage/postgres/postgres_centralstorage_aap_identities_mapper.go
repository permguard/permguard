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

package postgres

import (
	"fmt"
	"strings"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

var identitiesMap = map[string]int16{
	"user": 1,
	"role": 2,
}

// convertIdentityKindToID converts an identity kind to an ID.
func convertIdentityKindToID(kind string) (int16, error) {
	cKey := strings.ToLower(kind)
	value, ok := identitiesMap[cKey]
	if !ok {
		return 0, fmt.Errorf("storage: invalid identity kind. %w", azerrors.ErrClientGeneric)
	}
	return value, nil
}

// convertIdentityKindToString converts an identity kind to a string.
func convertIdentityKindToString(id int16) (string, error) {
	for k, v := range identitiesMap {
		if v == id {
			return k, nil
		}
	}
	return "", nil
}

// mapIdentityToAgentIdentity maps an Identity to a model Identity.
func mapIdentityToAgentIdentity(identity *Identity) (*azmodels.Identity, error) {
	kind, err := convertIdentityKindToString(identity.Kind)
	if err != nil {
		return nil, err
	}
	return &azmodels.Identity{
		IdentityID:       identity.IdentityID.String(),
		CreatedAt:        identity.CreatedAt,
		UpdatedAt:        identity.UpdatedAt,
		AccountID:        identity.AccountID,
		IdentitySourceID: identity.IdentitySourceID.String(),
		Kind:             kind,
		Name:             identity.Name,
	}, nil
}
