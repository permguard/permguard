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

package serializers

// Base is the base type.
type Base struct {
	Name string `yaml:"name"`
}

// GetName returns the name.
func (b Base) GetName() string {
	return b.Name
}

// Permission is the access control permission.
type Permission struct {
	Base
	Permit []string `yaml:"permit,omitempty"`
	Forbid []string `yaml:"forbid,omitempty"`
}

// Policy is the access control policy.
type Policy struct {
	Base
	Actions   []string `yaml:"actions,omitempty"`
	Resources []string	`yaml:"resources,omitempty"`
}
