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

// Package profiles defines the authorization profile identifiers used to describe
// the expected input model for policy evaluation within an authorization zone.
// A Profile is orthogonal to the policy language: it constrains the shape of
// the authorization request that policies in a partition are designed to evaluate.
package profiles

import "fmt"

const (
	// ProfileDefaultID is the default profile ID (0 = unset / no specific input model).
	ProfileDefaultID = uint32(0)
	// ProfileZtasApp is the name of the ZtasApp (ZTAUTH* App) profile.
	ProfileZtasApp = "profiles"
	// ProfileZtasAppID is the ID of the ZtasApp (ZTAUTH* App) profile.
	ProfileZtasAppID = uint32(1)
)

// ProfileName returns the display name for a profile ID.
// Returns an empty string for the default (0) ID and the decimal string representation
// for unknown IDs.
func ProfileName(id uint32) string {
	switch id {
	case ProfileDefaultID:
		return ""
	case ProfileZtasAppID:
		return ProfileZtasApp
	default:
		return fmt.Sprintf("%d", id)
	}
}
