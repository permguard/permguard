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

package authorization

import (
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
)

// StoreItem represents the store item.
type StoreItem struct {
	id   string
	object *azlangobjs.Object
}

// GetID returns the ID of the policy.
func (s *StoreItem) GetID() string {
	return s.id
}

// GetObject returns the object of the policy.
func (s *StoreItem) GetObject() *azlangobjs.Object {
	return s.object
}

// PolicyStore represents the policy store.
type PolicyStore struct {
	schema []StoreItem
	policies []StoreItem
}

// AddPolicy adds a policy to the policy store.
func (ps *PolicyStore) AddSchema(schemaID string, object *azlangobjs.Object) {
	policy := StoreItem{id: schemaID, object: object}
	ps.policies = append(ps.policies, policy)
}

// GetSchemas returns the schemas of the policy store.
func (ps *PolicyStore) GetSchemas() []StoreItem {
	return ps.schema
}

// AddPolicy adds a policy to the policy store.
func (ps *PolicyStore) AddPolicy(policyID string, object *azlangobjs.Object) {
	policy := StoreItem{id: policyID, object: object}
	ps.policies = append(ps.policies, policy)
}

// GetPolicies returns the policies of the policy store.
func (ps *PolicyStore) GetPolicies() []StoreItem {
	return ps.policies
}
