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

package validators

import (
	"fmt"
	"strings"

	"github.com/permguard/permguard/common/pkg/extensions/validators"
)

// ValidatePolicyName validates a policy name.
func ValidatePolicyName(name string) (bool, error) {
	sanitized := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, "permguard") {
		return false, fmt.Errorf("language: name %s is not valid. it cannot have 'permguard' as a prefix.", name)
	}
	if name != sanitized {
		return false, fmt.Errorf("language: name %s is not valid. it must be in lower case.", name)
	}
	vName := struct {
		Name string `validate:"required,name"`
	}{Name: name}
	if isValid, err := validators.ValidateInstance(vName); err != nil || !isValid {
		return false, fmt.Errorf("language: name %s is not valid.", vName.Name)
	}
	return true, nil
}
