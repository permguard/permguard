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
	azmodelsaap "github.com/permguard/permguard/pkg/transport/models/aap"
	azirepos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// mapIdentityToAgentIdentity maps an Identity to a model Identity.
func mapIdentityToAgentIdentity(identity *azirepos.Identity) (*azmodelsaap.Identity, error) {
	kind, err := azirepos.ConvertIdentityKindToString(identity.Kind)
	if err != nil {
		return nil, err
	}
	return &azmodelsaap.Identity{
		IdentityID:       identity.IdentityID,
		CreatedAt:        identity.CreatedAt,
		UpdatedAt:        identity.UpdatedAt,
		ApplicationID:    identity.ApplicationID,
		IdentitySourceID: identity.IdentitySourceID,
		Kind:             kind,
		Name:             identity.Name,
	}, nil
}
