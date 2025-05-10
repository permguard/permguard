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

// Subject represents the subject.
type Subject struct {
	subType    string
	id         string
	source     string
	properties map[string]any
}

// GetType returns the type of the subject.
func (s *Subject) GetType() string {
	return s.subType
}

// GetID returns the ID of the subject.
func (s *Subject) GetID() string {
	return s.id
}

// GetSource returns the source of the subject.
func (s *Subject) GetSource() string {
	return s.source
}

// GetProperties returns the properties of the subject.
func (s *Subject) GetProperties() map[string]any {
	return s.properties
}
