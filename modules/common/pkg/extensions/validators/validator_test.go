package validators

import (
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func TestIsSimpleName(t *testing.T) {
	assert := assert.New(t)

	validate := validator.New()
	validate.RegisterValidation("simplename", isSimpleName)

	// Test 1: Valid simple name
	err := validate.Var("abc123", "simplename")
	assert.Nil(err)

	// Test 2: Invalid simple name (contains uppercase letters)
	err = validate.Var("Abc123", "simplename")
	assert.NotNil(err)

	// Test 3: Invalid simple name (ends with non-alphanumeric)
	err = validate.Var("abc123-", "simplename")
	assert.NotNil(err)
}

func TestIsName(t *testing.T) {
	assert := assert.New(t)

	validate := validator.New()
	validate.RegisterValidation("name", isName)

	// Test 1: Valid name
	err := validate.Var("abc-123.name", "name")
	assert.Nil(err)

	// Test 2: Invalid name (starts with uppercase)
	err = validate.Var("Abc-123.name", "name")
	assert.NotNil(err)

	// Test 3: Invalid name (contains invalid character)
	err = validate.Var("abc@123.name", "name")
	assert.NotNil(err)
}

func TestIsWildcardName(t *testing.T) {
	assert := assert.New(t)

	validate := validator.New()
	validate.RegisterValidation("wildcardname", isWildcardName)

	// Test 1: Valid wildcard name
	err := validate.Var("abc-123.*name", "wildcardname")
	assert.Nil(err)

	// Test 2: Invalid wildcard name (starts with non-allowed character)
	err = validate.Var("-abc123", "wildcardname")
	assert.NotNil(err)

	// Test 3: Valid wildcard name with asterisk
	err = validate.Var("*abc-123", "wildcardname")
	assert.Nil(err)
}

func TestIsUUID(t *testing.T) {
	assert := assert.New(t)

	validate := validator.New()
	validate.RegisterValidation("isuuid", isUUID)

	// Test 1: Valid UUID
	err := validate.Var("550e8400-e29b-41d4-a716-446655440000", "isuuid")
	assert.Nil(err)

	// Test 2: Invalid UUID
	err = validate.Var("not-a-uuid", "isuuid")
	assert.NotNil(err)
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
	assert.Nil(err)

	// Test 2: Invalid instance (invalid UUID)
	instance.UUID = "invalid-uuid"
	valid, err = ValidateInstance(&instance)
	assert.False(valid)
	assert.NotNil(err)
}
