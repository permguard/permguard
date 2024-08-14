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
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// CreateIdentity creates a new identity.
func (s SQLiteCentralStorageAAP) CreateIdentity(identity *azmodels.Identity) (*azmodels.Identity, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}

// UpdateIdentity updates an identity.
func (s SQLiteCentralStorageAAP) UpdateIdentity(identity *azmodels.Identity) (*azmodels.Identity, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}

// DeleteIdentity deletes an identity.
func (s SQLiteCentralStorageAAP) DeleteIdentity(accountID int64, identityID string) (*azmodels.Identity, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}

// GetAllIdentities returns all identities.
func (s SQLiteCentralStorageAAP) GetAllIdentities(accountID int64, fields map[string]any) ([]azmodels.Identity, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}
