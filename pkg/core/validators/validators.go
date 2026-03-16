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

	cid "github.com/ipfs/go-cid"

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
	minVal := int64(100000000000)
	maxVal := int64(999999999999)
	if zoneID < minVal || zoneID > maxVal {
		return fmt.Errorf("validators: %s name %d is not valid. it must be between %d and %d", entity, zoneID, minVal, maxVal)
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

// ValidateOID validates an object identifier in CID format.
func ValidateOID(entity string, oid string) error {
	if strings.TrimSpace(oid) == "" {
		return fmt.Errorf("validators: %s OID is empty", entity)
	}
	_, err := cid.Decode(oid)
	if err != nil {
		return fmt.Errorf("validators: %s OID %s is not a valid CID", entity, oid)
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
	if len(name) > 255 {
		return fmt.Errorf("validators: %s name is too long (max 255 characters)", entity)
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("validators: %s name is not valid. it cannot be empty or contain only whitespace", entity)
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("validators: %s name %s is not valid. it cannot contain leading or trailing whitespace", entity, name)
	}
	sanitized := strings.ToLower(name)
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
