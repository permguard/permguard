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

package manifest

import (
	"fmt"
	"regexp"
)

// Requirement it represents the requirement.
type Requirement struct {
	name    string
	version string
}

// newRequirement create a new instance of the requirement.
func newRequirement(name, version string) *Requirement {
	return &Requirement{name: name, version: version}
}

// GetName gets the name.
func (r *Requirement) GetName() string {
	return r.name
}

// GetVersion gets the version.
func (r *Requirement) GetVersion() string {
	return r.version
}

var re = regexp.MustCompile(`^(\w+)(?:\[(\d+\.\d+\+?)\])?$`)

// ParseRequirement parse the input requirement.
func ParseRequirement(s string) (*Requirement, error) {
	matches := re.FindStringSubmatch(s)
	if len(matches) == 0 {
		return nil, fmt.Errorf("invalid requirement format: %s", s)
	}
	return newRequirement(matches[1], matches[2]), nil
}
