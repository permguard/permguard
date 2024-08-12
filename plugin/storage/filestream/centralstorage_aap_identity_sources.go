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

package filestream

import (
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

const (
	IdentitySourceDefaultName = "default"
)

// CreateIdentitySource creates a new identity source.
func (s FileStreamCentralStorageAAP) CreateIdentitySource(identitySource *azmodels.IdentitySource) (*azmodels.IdentitySource, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}

// UpdateIdentitySource updates an identity source.
func (s FileStreamCentralStorageAAP) UpdateIdentitySource(identitySource *azmodels.IdentitySource) (*azmodels.IdentitySource, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}

// DeleteIdentitySource deletes an identity source.
func (s FileStreamCentralStorageAAP) DeleteIdentitySource(accountID int64, identitySourceID string) (*azmodels.IdentitySource, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}

// GetAllIdentitySources returns all identity sources.
func (s FileStreamCentralStorageAAP) GetAllIdentitySources(accountID int64, fields map[string]any) ([]azmodels.IdentitySource, error) {
	// logger := s.ctx.GetLogger()
	return nil, nil
}
