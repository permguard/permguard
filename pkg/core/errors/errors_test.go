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
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsErrorInClass tests the IsErrorInClass function.
func TestIsErrorInClass(t *testing.T) {
	assert := assert.New(t)
	testCases := []struct {
		mask     string
		err      error
		expected bool
	}{
		{"01xxx", errors.New("not a valid error"), false},
		{ZeroErrorCode, ErrUnknown, true},
		{ZeroErrorCode, fmt.Errorf("%q: %w", "sample", ErrUnknown), true},
		{"000xx", ErrUnknown, true},
		{"00xxx", ErrUnknown, true},
		{"01xxx", ErrUnknown, false},
		{"0211x", ErrUnknown, false},

		{"04xxx", ErrClientEntity, true},
		{"041xx", ErrClientEntity, true},
		{"0412x", ErrClientEntity, false},
		{"041xx", ErrClientID, true},
		{"041xx", ErrClientName, true},
	}
	for _, tc := range testCases {
		result := IsErrorInClass(tc.err, tc.mask)
		assert.True(result == tc.expected, "isErrorInClass(%s, %q) = %v (expected %v)", tc.mask, tc.err, result, tc.expected)
	}
}

// TestNewSystemErrorWithMessage tests the NewSystemErrorWithMessage function.
func TestNewSystemErrorWithMessage(t *testing.T) {
	assert := assert.New(t)
	testCases := []struct {
		code            string
		message         string
		expectedCode    string
		expectedMessage string
	}{
		{ZeroErrorCode, "", ZeroErrorCode, "core: unknown error"},
		{ZeroErrorCode, "not valid", ZeroErrorCode, "core: not valid"},
		{"00191", "", "00191", "code: generic error"},
		{"00181", "not valid", "00181", "code: not valid"},
		{"04100", "not valid", "04100", "client: not valid"},
		{"04151", "new custom error", "04151", "client: new custom error"},
	}
	for _, tc := range testCases {
		result := ConvertToSystemError(NewSystemErrorWithMessage(tc.code, tc.message))
		assert.True(result.errCode == tc.expectedCode, "NewSystemErrorWithMessage(%q, %s) = %d (expected %d)", tc.code, tc.message, result.errCode, tc.expectedCode)
		assert.True(result.errMessage == tc.expectedMessage, "NewSystemErrorWithMessage(%q, %s) = %s (expected %s)", tc.code, tc.message, result.errMessage, tc.expectedMessage)
	}
}

// TestNewSystemError tests the NewSystemError function.
func TestNewSystemError(t *testing.T) {
	assert := assert.New(t)
	testCases := []struct {
		err      error
		expected bool
	}{
		{errors.New("This is a simple error"), false},
		{ErrClientID, true},
		{fmt.Errorf("%q: %w", "sample", ErrClientID), true},
		{fmt.Errorf("%q: %w", "sample2", fmt.Errorf("%q: %w", "sample1", ErrClientID)), true},
	}
	for _, tc := range testCases {
		sysErr := ConvertToSystemError(tc.err)
		if tc.expected {
			assert.True(sysErr != nil, "ConvertToSystemError(%s) = %v (expected not nil)", tc.err, sysErr)
		} else {
			assert.True(sysErr == nil, "ConvertToSystemError(%s) = %v (expected %v)", tc.err, sysErr, nil)
		}
	}
}

// TestSystemError tests system errors.
func TestSystemError(t *testing.T) {
	assert := assert.New(t)
	testCases := []struct {
		code            string
		expectedCode    string
		expectedMessage string
	}{
		{ZeroErrorCode, ZeroErrorCode, "core: unknown error"},
		{"00181", "00181", "code: generic error"},
		{"04141", "04141", "client: invalid client parameter"},
		{"04101", "04101", "client: invalid pagination parameter"},
	}
	for _, tc := range testCases {
		result := ConvertToSystemError(NewSystemError(tc.code))
		assert.True(result.errCode == tc.expectedCode, "NewSystemError(%d, %s) = %d (expected %d)", tc.code, tc.expectedCode)
		assert.True(result.errMessage == tc.expectedMessage, "NewSystemError(%d, %s) = %s (expected %s)", tc.code, tc.expectedMessage)
	}
}
