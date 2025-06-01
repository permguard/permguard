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

package authzen

import (
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// StoreItem represents the store item.
type StoreItem struct {
	objectInfo *objects.ObjectInfo
}

// ObjectInfo returns the object info of the store item.
func (s *StoreItem) ObjectInfo() *objects.ObjectInfo {
	return s.objectInfo
}

// PolicyStore represents the policy store.
type PolicyStore struct {
	schemas  []StoreItem
	version  string
	policies []StoreItem
}

// AddSchema adds a schema to the policy store.
func (ps *PolicyStore) AddSchema(schemaID string, objectInfo *objects.ObjectInfo) {
	schema := StoreItem{objectInfo: objectInfo}
	ps.schemas = append(ps.schemas, schema)
}

// Schemas returns the schemas of the policy store.
func (ps *PolicyStore) Schemas() []StoreItem {
	return ps.schemas
}

// SetVersion sets the version of the policy store.
func (ps *PolicyStore) SetVersion(version string) {
	ps.version = version
}

// Version returns the version of the policy store.
func (ps *PolicyStore) Version() string {
	return ps.version
}

// AddPolicy adds a policy to the policy store.
func (ps *PolicyStore) AddPolicy(policyID string, objectInfo *objects.ObjectInfo) {
	policy := StoreItem{objectInfo: objectInfo}
	ps.policies = append(ps.policies, policy)
}

// Policies returns the policies of the policy store.
func (ps *PolicyStore) Policies() []StoreItem {
	return ps.policies
}
