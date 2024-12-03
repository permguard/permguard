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

	azvalidators "github.com/permguard/permguard-core/pkg/extensions/validators"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// ValidateCodeID validates an account ID.
func ValidateCodeID(entity string, accountID int64) error {
	vAccountID := struct {
		AccountID int64 `validate:"required,gt=0"`
	}{AccountID: accountID}
	if isValid, err := azvalidators.ValidateInstance(vAccountID); err != nil || !isValid {
		return fmt.Errorf("storage: %s name %d is not valid. %w", entity, vAccountID.AccountID, azerrors.ErrClientID)
	}
	min := int64(100000000000)
	max := int64(999999999999)
	if accountID < min || accountID > max {
		return fmt.Errorf("storage: %s name %d is not valid. it must be between %d and %d. %w", entity, accountID, min, max, azerrors.ErrClientID)
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
		return fmt.Errorf("storage: %s hash %s is not valid. %w", entity, hash, azerrors.ErrClientSHA256)
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("storage: %s hash %s contains invalid characters. %w", entity, hash, azerrors.ErrClientSHA256)
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
	if isValid, err := azvalidators.ValidateInstance(vID); err != nil || !isValid {
		return fmt.Errorf("storage: %s name %s is not valid. %w", entity, vID.ID, azerrors.ErrClientUUID)
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
	if isValid, err := azvalidators.ValidateInstance(vEmail); err != nil || !isValid {
		return fmt.Errorf("storage: %s identity name %s is not valid. %w", entity, vEmail.Email, azerrors.ErrClientName)
	}
	return nil
}

// ValidateName validates a name.
func ValidateName(entity string, name string) error {
	sanitized := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, "permguard") {
		return fmt.Errorf("storage: %s name %s is not valid. it cannot have 'permguard' as a prefix. %w", entity, name, azerrors.ErrClientName)
	}
	if name != sanitized {
		return fmt.Errorf("storage: %s name %s is not valid. it must be in lower case. %w", entity, name, azerrors.ErrClientName)
	}
	vName := struct {
		Name string `validate:"required,name"`
	}{Name: name}
	if isValid, err := azvalidators.ValidateInstance(vName); err != nil || !isValid {
		return fmt.Errorf("storage: %s name %s is not valid. %w", entity, vName.Name, azerrors.ErrClientName)
	}
	return nil
}
