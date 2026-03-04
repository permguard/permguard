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

func TestMergeMaps(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Merge two non-overlapping maps
	dest := map[string]any{"a": 1, "b": 2}
	src := map[string]any{"c": 3, "d": 4}
	merged := MergeMaps(dest, src)
	assert.Equal(map[string]any{"a": 1, "b": 2, "c": 3, "d": 4}, merged)

	// Test 2: Src overwrites conflicting keys from dest
	dest = map[string]any{"a": 1, "b": 2}
	src = map[string]any{"b": 99, "c": 3}
	merged = MergeMaps(dest, src)
	assert.Equal(map[string]any{"a": 1, "b": 99, "c": 3}, merged)

	// Test 3: Merge with empty dest
	dest = map[string]any{}
	src = map[string]any{"a": 1}
	merged = MergeMaps(dest, src)
	assert.Equal(map[string]any{"a": 1}, merged)

	// Test 4: Merge with empty src
	dest = map[string]any{"a": 1}
	src = map[string]any{}
	merged = MergeMaps(dest, src)
	assert.Equal(map[string]any{"a": 1}, merged)

	// Test 5: Merge two empty maps
	dest = map[string]any{}
	src = map[string]any{}
	merged = MergeMaps(dest, src)
	assert.Equal(map[string]any{}, merged)

	// Test 6: Original maps should not be mutated
	dest = map[string]any{"a": 1}
	src = map[string]any{"b": 2}
	merged = MergeMaps(dest, src)
	merged["c"] = 3
	assert.NotContains(dest, "c")
	assert.NotContains(src, "c")
}
