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

package files

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	azpolicies "github.com/permguard/permguard/pkg/accesscontrol/policies"
)

func TestJsonSchemaValidationForValid(t *testing.T) {
	tests := map[string]struct {
		Path string
	}{
		string(azpolicies.PolicyV1): {
			"./testdata/extensions/files/validate-jsonschema/valid",
		},
	}
	for version, test := range tests {
		testDataVersionPath := test.Path + "/" + version
		cases, _ := os.ReadDir(testDataVersionPath)
		for _, c := range cases {
			caseName := c.Name()
			testDataCasePath := testDataVersionPath + "/" + caseName

			inputs, _ := os.ReadDir(testDataCasePath)
			for _, input := range inputs {
				inputName := input.Name()
				testDataCaseInputPath := testDataCasePath + "/" + inputName
				t.Run(strings.ToUpper(version+"-"+caseName+"-"+inputName), func(t *testing.T) {
					assert := assert.New(t)
					bArray, _ := os.ReadFile(testDataCaseInputPath)
					isValid, err := IsValidJSON(azpolicies.ACPolicySchema, bArray)
					assert.Nil(err, "wrong result\nshould be nil")
					assert.True(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(isValid))
				})
			}
		}
	}
}

func TestJsonSchemaValidationForNotValid(t *testing.T) {
	tests := map[string]struct {
		Path string
	}{
		string(azpolicies.PolicyV1): {
			"./testdata/extensions/files/validate-jsonschema/notvalid",
		},
	}
	for version, test := range tests {
		testDataVersionPath := test.Path + "/" + version
		cases, _ := os.ReadDir(testDataVersionPath)
		for _, c := range cases {
			caseName := c.Name()
			testDataCasePath := testDataVersionPath + "/" + caseName

			inputs, _ := os.ReadDir(testDataCasePath)
			for _, input := range inputs {
				inputName := input.Name()
				testDataCaseInputPath := testDataCasePath + "/" + inputName
				t.Run(strings.ToUpper(version+"-"+caseName+"-"+inputName), func(t *testing.T) {
					assert := assert.New(t)
					bArray, _ := os.ReadFile(testDataCaseInputPath)
					isValid, err := IsValidJSON(azpolicies.ACPolicySchema, bArray)
					assert.Nil(err, "wrong result\nshould be nil")
					assert.False(isValid, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
				})
			}
		}
	}
}

func TestMiscellaneousPermissionsLoader(t *testing.T) {
	assert := assert.New(t)
	var err error
	{
		_, err = IsValidJSON(nil, nil)
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.True(errors.Is(err, ErrFilesJSONSchemaValidation), "wrong result\ngot: %sshould be of type ErrFilesJSONSchemaValidation", spew.Sdump(err))
	}
}
