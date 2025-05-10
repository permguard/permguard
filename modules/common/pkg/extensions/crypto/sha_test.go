package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeSHA256(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Verify SHA256 hash of empty data
	data := []byte("")
	expectedHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	result := ComputeSHA256(data)
	assert.Equal(expectedHash, result)

	// Test 2: Verify SHA256 hash of specific data
	data = []byte("Hello, World!")
	expectedHash = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
	result = ComputeSHA256(data)
	assert.Equal(expectedHash, result)
}

func TestComputeStringSHA256(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Verify SHA256 hash of an empty string
	data := ""
	expectedHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	result := ComputeStringSHA256(data)
	assert.Equal(expectedHash, result)

	// Test 2: Verify SHA256 hash of a specific string
	data = "Hello, World!"
	expectedHash = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
	result = ComputeStringSHA256(data)
	assert.Equal(expectedHash, result)
}
