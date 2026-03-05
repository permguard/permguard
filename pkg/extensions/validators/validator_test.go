// Copyright 2025 Nitro Agility S.r.l.
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
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsSimpleName(t *testing.T) {
	assert := assert.New(t)

	validate := validator.New()
	assert.NoError(validate.RegisterValidation("simplename", isSimpleName))

	// Test 1: Valid simple name
	err := validate.Var("abc123", "simplename")
	assert.NoError(err)

	// Test 2: Invalid simple name (contains uppercase letters)
	err = validate.Var("Abc123", "simplename")
	assert.Error(err)

	// Test 3: Invalid simple name (ends with non-alphanumeric)
	err = validate.Var("abc123-", "simplename")
	assert.Error(err)
}

func TestIsName(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	validate := validator.New()
	require.NoError(validate.RegisterValidation("name", isName))

	// Test 1: Valid name
	err := validate.Var("abc-123.name", "name")
	require.NoError(err)

	// Test 2: Invalid name (starts with uppercase)
	err = validate.Var("Abc-123.name", "name")
	require.Error(err)

	// Test 3: Invalid name (contains invalid character)
	err = validate.Var("abc@123.name", "name")
	assert.Error(err)
}

func TestIsWildcardName(t *testing.T) {
	validate := validator.New()
	require.NoError(t, validate.RegisterValidation("wildcardname", isWildcardName))

	// Test 1: Valid wildcard name
	err := validate.Var("abc-123.*name", "wildcardname")
	require.NoError(t, err)

	// Test 2: Invalid wildcard name (starts with non-allowed character)
	err = validate.Var("-abc123", "wildcardname")
	require.Error(t, err)

	// Test 3: Valid wildcard name with asterisk
	err = validate.Var("*abc-123", "wildcardname")
	require.NoError(t, err)
}

func TestIsUUID(t *testing.T) {
	assert := assert.New(t)

	validate := validator.New()
	assert.NoError(validate.RegisterValidation("isuuid", isUUID))

	// Test 1: Valid UUID
	err := validate.Var("550e8400-e29b-41d4-a716-446655440000", "isuuid")
	assert.NoError(err)

	// Test 2: Invalid UUID
	err = validate.Var("not-a-uuid", "isuuid")
	assert.Error(err)
}

func TestValidateInstance(t *testing.T) {
	assert := assert.New(t)

	type TestStruct struct {
		SimpleName   string `validate:"simplename"`
		Name         string `validate:"name"`
		WildcardName string `validate:"wildcardname"`
		UUID         string `validate:"isuuid"`
	}

	// Test 1: Valid instance
	instance := TestStruct{
		SimpleName:   "abc123",
		Name:         "abc-123.name",
		WildcardName: "*abc123",
		UUID:         "550e8400-e29b-41d4-a716-446655440000",
	}
	valid, err := ValidateInstance(&instance)
	assert.True(valid)
	assert.NoError(err)

	// Test 2: Invalid instance (invalid UUID)
	instance.UUID = "invalid-uuid"
	valid, err = ValidateInstance(&instance)
	assert.False(valid)
	assert.Error(err)
}
