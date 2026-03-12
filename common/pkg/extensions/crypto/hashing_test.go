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

func TestComputeCID(t *testing.T) {
	assert := assert.New(t)

	// Test 1: CID of empty data
	result, err := ComputeCID([]byte(""))
	assert.NoError(err)
	assert.Equal("bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku", result)

	// Test 2: CID of specific data
	result, err = ComputeCID([]byte("Hello, World!"))
	assert.NoError(err)
	assert.Equal("bafyreig77vqcdozl2wyk6z3cscaj5q5fggi53aoh64fewkdiri3cdauyn4", result)

	// Test 3: Same content always produces the same CID
	result1, _ := ComputeCID([]byte("test"))
	result2, _ := ComputeCID([]byte("test"))
	assert.Equal(result1, result2)
}

func TestComputeStringCID(t *testing.T) {
	assert := assert.New(t)

	result, err := ComputeStringCID("Hello, World!")
	assert.NoError(err)
	expected, _ := ComputeCID([]byte("Hello, World!"))
	assert.Equal(expected, result)
}

func TestVerifyCID(t *testing.T) {
	assert := assert.New(t)

	data := []byte("Hello, World!")
	validCID, err := ComputeCID(data)
	assert.NoError(err)

	// Test 1: Verification succeeds with correct content
	err = VerifyCID(validCID, data)
	assert.NoError(err)

	// Test 2: Verification fails with wrong content
	err = VerifyCID(validCID, []byte("wrong data"))
	assert.Error(err)
	assert.Contains(err.Error(), "CID mismatch")

	// Test 3: Verification fails with invalid CID string
	err = VerifyCID("invalid-cid", data)
	assert.Error(err)
	assert.Contains(err.Error(), "failed to decode CID")
}

func TestZeroCID(t *testing.T) {
	assert := assert.New(t)

	// ZeroCID should be a valid, non-empty CID string
	assert.NotEmpty(ZeroCID)
	assert.Equal("bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ZeroCID)
}
