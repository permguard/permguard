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

package copier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCopySlice(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Copy an empty slice
	originalSlice := []int{}
	copiedSlice := CopySlice(originalSlice)
	assert.Equal(originalSlice, copiedSlice)

	// Test 2: Copy a non-empty slice
	originalSlice = []int{1, 2, 3, 4}
	copiedSlice = CopySlice(originalSlice)
	assert.Equal(originalSlice, copiedSlice)

	// Modify the original slice and verify the copied slice is not affected
	originalSlice[0] = 100
	assert.NotEqual(originalSlice, copiedSlice)
}

func TestCopyMap(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Copy an empty map
	originalMap := map[string]int{}
	copiedMap := CopyMap(originalMap)
	assert.Equal(originalMap, copiedMap)

	// Test 2: Copy a non-empty map
	originalMap = map[string]int{"a": 1, "b": 2}
	copiedMap = CopyMap(originalMap)
	assert.Equal(originalMap, copiedMap)

	// Modify the original map and verify the copied map is not affected
	originalMap["a"] = 100
	assert.NotEqual(originalMap, copiedMap)
}

func TestCopy(t *testing.T) {
	assert := assert.New(t)

	// Define two structs to test copying
	type Person struct {
		Name string
		Age  int
	}

	// Test 1: Copy struct fields from one struct to another
	from := Person{Name: "John", Age: 30}
	to := Person{}

	err := Copy(&to, &from)
	assert.NoError(err)
	assert.Equal(from, to)

	// Modify the original struct and verify the copied struct is not affected
	from.Name = "Jane"
	assert.NotEqual(from, to)
}
