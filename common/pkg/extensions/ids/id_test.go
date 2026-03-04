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

package ids

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateID(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Generated ID should be a 32-character hexadecimal string
	id := GenerateID()
	assert.Len(id, 32)

	// Test 2: Generated ID should only contain valid hexadecimal characters
	hexPattern := regexp.MustCompile(`^[0-9a-f]{32}$`)
	assert.True(hexPattern.MatchString(id))

	// Test 3: Two generated IDs should be unique
	id2 := GenerateID()
	assert.NotEqual(id, id2)

	// Test 4: Generated ID should not contain hyphens
	assert.NotContains(id, "-")
}
