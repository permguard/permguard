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

package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompressData(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Compress empty data returns empty slice without error
	compressed, err := CompressData([]byte{})
	assert.NoError(err)
	assert.Equal([]byte{}, compressed)

	// Test 2: Compress non-empty data returns non-empty result without error
	data := []byte("Hello, World!")
	compressed, err = CompressData(data)
	assert.NoError(err)
	assert.NotEmpty(compressed)

	// Test 3: Compressed data should differ from original data
	assert.NotEqual(data, compressed)

	// Test 4: Compress nil data returns empty slice without error
	compressed, err = CompressData(nil)
	assert.NoError(err)
	assert.Equal([]byte{}, compressed)
}

func TestDecompressData(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Decompress empty data returns empty slice without error
	decompressed, err := DecompressData([]byte{})
	assert.NoError(err)
	assert.Equal([]byte{}, decompressed)

	// Test 2: Decompress nil data returns empty slice without error
	decompressed, err = DecompressData(nil)
	assert.NoError(err)
	assert.Equal([]byte{}, decompressed)

	// Test 3: Decompress invalid data returns an error
	_, err = DecompressData([]byte("invalid zlib data"))
	assert.Error(err)
}

func TestCompressDecompressData(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Compress and decompress returns original data
	original := []byte("Hello, World!")
	compressed, err := CompressData(original)
	assert.NoError(err)
	assert.NotEmpty(compressed)

	decompressed, err := DecompressData(compressed)
	assert.NoError(err)
	assert.Equal(original, decompressed)

	// Test 2: Compress and decompress a larger payload
	largeData := make([]byte, 10000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	compressed, err = CompressData(largeData)
	assert.NoError(err)
	assert.NotEmpty(compressed)

	decompressed, err = DecompressData(compressed)
	assert.NoError(err)
	assert.Equal(largeData, decompressed)

	// Test 3: Compress and decompress data with repeated patterns
	repeatedData := []byte("abcabcabcabcabcabcabcabcabcabc")
	compressed, err = CompressData(repeatedData)
	assert.NoError(err)
	assert.NotEmpty(compressed)

	decompressed, err = DecompressData(compressed)
	assert.NoError(err)
	assert.Equal(repeatedData, decompressed)
}
