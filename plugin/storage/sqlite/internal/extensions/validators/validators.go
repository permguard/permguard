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

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azvalidators "github.com/permguard/permguard/pkg/extensions/validators"
)

// ValidateAccountID validates an account ID.
func ValidateAccountID(entity string, accountID int64) error {
	vAccountID := struct {
		AccountID int64 `validate:"required,gt=0"`
	}{AccountID: accountID}
	if isValid, err := azvalidators.ValidateInstance(vAccountID); err != nil || !isValid {
		return fmt.Errorf("storage: %s name %d is not valid. %w", entity, vAccountID.AccountID, azerrors.ErrClientAccountID)
	}
	return nil
}

// ValidateUUID validates a UUID.
func ValidateUUID(entity string, id string) error {
	vID := struct {
		ID string `validate:"required,uuid4"`
	}{ID: id}
	if isValid, err := azvalidators.ValidateInstance(vID); err != nil || !isValid {
		return fmt.Errorf("storage: %s name %s is not valid. %w", entity, vID.ID, azerrors.ErrClientUUID)
	}
	return nil
}

// ValidateName validates a name.
func ValidateName(entity string, name string) error {
	if name != strings.ToLower(name) {
		return fmt.Errorf("storage: %s name %s is not valid. It must be in lower case. %w", entity, name, azerrors.ErrClientName)
	}
	vName := struct {
		Name string `validate:"required,name"`
	}{Name: name}
	if isValid, err := azvalidators.ValidateInstance(vName); err != nil || !isValid {
		return fmt.Errorf("storage: %s name %s is not valid. %w", entity, vName.Name, azerrors.ErrClientName)
	}
	return nil
}
