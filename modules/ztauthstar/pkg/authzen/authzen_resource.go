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

// Resource represents the resource.
type Resource struct {
	resType    string
	id         string
	properties map[string]any
}

// GetType returns the type of the resource.
func (r *Resource) GetType() string {
	return r.resType
}

// GetID returns the ID of the resource.
func (r *Resource) GetID() string {
	return r.id
}

// GetProperties returns the properties of the resource.
func (r *Resource) GetProperties() map[string]any {
	return r.properties
}
