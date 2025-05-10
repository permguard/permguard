package validators

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidPath(t *testing.T) {
	assert := assert.New(t)

	// Test !: Invalid path
	isValid := IsValidPath("/")
	assert.True(isValid)

	// Test 2: Invalid path
	isValid = IsValidPath("/valid/path")
	assert.False(isValid)

	// Test 3: Invalid path (empty string)
	isValid = IsValidPath("")
	assert.False(isValid)
}

func TestIsValidPort(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Valid port
	isValid := IsValidPort(8080)
	assert.True(isValid)

	// Test 2: Invalid port (out of range)
	isValid = IsValidPort(70000)
	assert.False(isValid)
}

func TestIsValidHostname(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Valid hostname
	isValid := IsValidHostname("example.com")
	assert.True(isValid)

	// Test 2: Invalid hostname (empty string)
	isValid = IsValidHostname("")
	assert.False(isValid)
}

func TestIsValidHostnamePort(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Valid hostname with port
	isValid := IsValidHostnamePort("example.com:8080")
	assert.True(isValid)

	// Test 2: Invalid hostname with port (empty string)
	isValid = IsValidHostnamePort("")
	assert.False(isValid)
}

func TestValidateSimpleName(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Valid simple name
	isValid := ValidateSimpleName("simple123")
	assert.True(isValid)

	// Test 2: Invalid simple name (uppercase letters)
	isValid = ValidateSimpleName("Simple123")
	assert.False(isValid)
}

func TestValidateCodeID(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Valid code id
	isValid := ValidateCodeID(123456789012)
	assert.True(isValid)

	// Test 2: Invalid code id (out of range)
	isValid = ValidateCodeID(9999999999999)
	assert.False(isValid)

	// Test 3: Invalid code id (negative value)
	isValid = ValidateCodeID(-123456789012)
	assert.False(isValid)
}

func TestFormatAsUUID(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Format a valid UUID
	formatted := formatAsUUID("550e8400e29b41d4a716446655440000")
	assert.Equal("550e8400-e29b-41d4-a716-446655440000", formatted)

	// Test 2: Return original string if already formatted
	formatted = formatAsUUID("550e8400-e29b-41d4-a716-446655440000")
	assert.Equal("550e8400-e29b-41d4-a716-446655440000", formatted)
}

func TestValidateUUID(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Valid UUID
	isValid := ValidateUUID("550e8400e29b41d4a716446655440000")
	assert.True(isValid)

	// Test 2: Invalid UUID (incorrect format)
	isValid = ValidateUUID("invalid-uuid")
	assert.False(isValid)
}

func TestValidateIdentityUserName(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Valid identity username (email format)
	isValid := ValidateIdentityUserName("user@example.com")
	assert.True(isValid)

	// Test 2: Valid identity username (regular name)
	isValid = ValidateIdentityUserName("validname123")
	assert.True(isValid)

	// Test 3: Invalid identity username (invalid email)
	isValid = ValidateIdentityUserName("invalid@email")
	assert.False(isValid)
}

func TestValidateName(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Valid name
	isValid := ValidateName("validname")
	assert.True(isValid)

	// Test 2: Invalid name (contains uppercase)
	isValid = ValidateName("InvalidName")
	assert.False(isValid)

	// Test 3: Invalid name (starts with "permguard")
	isValid = ValidateName("permguardname")
	assert.False(isValid)
}

func TestValidateWildcardName(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Valid wildcard name
	isValid := ValidateWildcardName("*validname")
	assert.True(isValid)

	// Test 2: Invalid wildcard name (contains uppercase)
	isValid = ValidateWildcardName("*InvalidName")
	assert.False(isValid)

	// Test 3: Invalid wildcard name (starts with "permguard")
	isValid = ValidateWildcardName("permguardname")
	assert.False(isValid)
}
