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

package errors

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsErrorCodeDefined tests the isErrorCodeDefined function.
func TestIsErrorCodeDefined(t *testing.T) {
	assert := assert.New(t)
	testCases := []struct {
		errCode  string
		expected bool
	}{
		{"-1", false},
		{"01", false},
		{"0122342342342", false},
		{"01223a42342342", false},
		{"00000", true},
		{"00105", false},
	}
	for _, tc := range testCases {
		result := isErrorCodeDefined(tc.errCode)
		assert.True(result == tc.expected, "isErrorCodeDefined(%d) = %v (expected %v)", tc.errCode, result, tc.expected)
	}
}
