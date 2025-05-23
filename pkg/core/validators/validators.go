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

// ValidateCodeID validates a zone ID.
func ValidateCodeID(entity string, zoneID int64) error {
	vZoneID := struct {
		ZoneID int64 `validate:"required,gt=0"`
	}{ZoneID: zoneID}
	if isValid, err := validators.ValidateInstance(vZoneID); err != nil || !isValid {
		return fmt.Errorf("validators: %s name %d is not valid", entity, vZoneID.ZoneID)
	}
	min := int64(100000000000)
	max := int64(999999999999)
	if zoneID < min || zoneID > max {
		return fmt.Errorf("validators: %s name %d is not valid. it must be between %d and %d", entity, zoneID, min, max)
	}
	return nil
}

// formatAsUUID formats a string as a UUID.
func formatAsUUID(s string) string {
	if strings.Contains(s, "-") || strings.Contains(s, " ") || len(s) != 32 {
		return s
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		s[0:8],
		s[8:12],
		s[12:16],
		s[16:20],
		s[20:32],
	)
}

// ValidateSHA256 validates a SHA256 hash.
func ValidateSHA256(entity string, hash string) error {
	if len(hash) != 64 {
		return fmt.Errorf("validators: %s hash %s is not valid", entity, hash)
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("validators: %s hash %s contains invalid characters", entity, hash)
		}
	}
	return nil
}

// ValidateUUID validates a UUID.
func ValidateUUID(entity string, id string) error {
	formattedID := formatAsUUID(id)
	vID := struct {
		ID string `validate:"required,uuid4"`
	}{ID: formattedID}
	if isValid, err := validators.ValidateInstance(vID); err != nil || !isValid {
		return fmt.Errorf("validators: %s name %s is not valid", entity, vID.ID)
	}
	return nil
}

// ValidateIdentityUserName validates the identity name specifically for user-type identities.
func ValidateIdentityUserName(entity string, name string) error {
	err := ValidateName(entity, name)
	if err == nil {
		return nil
	}
	vEmail := struct {
		Email string `validate:"required,email"`
	}{Email: name}
	if isValid, err := validators.ValidateInstance(vEmail); err != nil || !isValid {
		return fmt.Errorf("validators: %s identity name %s is not valid", entity, vEmail.Email)
	}
	return nil
}

// ValidateName validates a name.
func ValidateName(entity string, name string) error {
	sanitized := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, "permguard") {
		return fmt.Errorf("validators: %s name %s is not valid. it cannot have 'permguard' as a prefix", entity, name)
	}
	if name != sanitized {
		return fmt.Errorf("validators: %s name %s is not valid. it must be in lower case", entity, name)
	}
	vName := struct {
		Name string `validate:"required,name"`
	}{Name: name}
	if isValid, err := validators.ValidateInstance(vName); err != nil || !isValid {
		return fmt.Errorf("validators: %s name %s is not valid", entity, vName.Name)
	}
	return nil
}
