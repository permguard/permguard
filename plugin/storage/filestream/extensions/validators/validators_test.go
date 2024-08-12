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

package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

// TestValidateAccountID tests the validateAccountID function.
func TestValidateAccountID(t *testing.T) {
	assert := assert.New(t)

	testCases := []struct {
		entity    string
		accountID int
		hasError  bool
	}{
		{"account", -15000, true},
		{"account", -1, true},
		{"account", 0, true},
		{"account", 1, false},
		{"account", 15000, false},
		{"", 15000, false},
	}
	for _, tc := range testCases {
		result := validateAccountID(tc.entity, int64(tc.accountID))
		if tc.hasError {
			assert.NotNil(result, "error should not be nil")
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientAccountID, result), "error should be ErrClientAccountID")
		} else {
			assert.Nil(result, "error should be nil")
		}
	}
}

// TestValidateUUID tests the validateUUID function.
func TestValidateUUID(t *testing.T) {
	assert := assert.New(t)

	testCases := []struct {
		entity   string
		UUID     string
		hasError bool
	}{
		{"account", "", true},
		{"account", " ", true},
		{"account", "-15000", true},
		{"account", "15000", true},
		{"account", "5e6c75ca-caeb-4f85-8007-Zdcf6bb1beff", true},
		{"account", "d3967c8f54dc4a28bf3ca1dZca94fa95", true},
		{"account", "f12bf1c12da44a9a97043650824b0a0b", true},
		{"account", "ddd0e6a0-956b-4967-84a0-15c5e54b0b50", false},
		{"", "ddd0e6a0-956b-4967-84a0-15c5e54b0b50", false},
	}
	for _, tc := range testCases {
		result := validateUUID(tc.entity, tc.UUID)
		if tc.hasError {
			assert.NotNil(result, "error should not be nil")
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientUUID, result), "error should be ErrClientUUID")
		} else {
			assert.Nil(result, "error should be nil")
		}
	}
}

// TestValidateName tests the validateName function.
func TestValidateName(t *testing.T) {
	assert := assert.New(t)

	testCases := []struct {
		entity   string
		name     string
		hasError bool
	}{
		{"account", "", true},
		{"account", " s s d  ", true},
		{"account", "132465", true},
		{"account", "13a2aa465", true},
		{"account", "nome-@nonvalido", true},
		{"account", "nome/nonvalido", true},
		{"account", "nome", false},
		{"account", "nome-valido", false},
		{"", "nome-valido", false},
	}
	for _, tc := range testCases {
		result := validateName(tc.entity, tc.name)
		if tc.hasError {
			assert.NotNil(result, "error should not be nil")
			assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientName, result), "error should be ErrClientName")
		} else {
			assert.Nil(result, "error should be nil")
		}
	}
}
