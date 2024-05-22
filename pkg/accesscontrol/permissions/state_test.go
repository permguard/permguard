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

package permissions

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"

	azpolicies "github.com/permguard/permguard/pkg/accesscontrol/policies"
)

func helperToCompareACPolicyStatementWrappers(file string, inputList []ACPolicyStatementWrapper) error {
	uniqueFobid := make(map[string]bool)
	for _, forbid := range inputList {
		key := forbid.StatmentHashed
		if uniqueFobid[key] {
			return errors.New("permission: duplicated key: " + spew.Sdump(key))
		}
		uniqueFobid[key] = true
	}
	bArray, _ := os.ReadFile(file)
	data := []azpolicies.ACPolicyStatement{}
	_ = json.Unmarshal(bArray, &data)
	if len(data) != len(inputList) {
		return errors.New("permission: missing key as size does not match")
	}
	for _, forbid := range data {
		fobidWrapper, _ := createACPolicyStatementWrapper(&forbid)
		key := fobidWrapper.StatmentHashed
		if !uniqueFobid[key] {
			return errors.New("permission: missing key: " + spew.Sdump(key))
		}
	}
	return nil
}

func TestCreatePermissionsState(t *testing.T) {
	tests := map[string]struct {
		Name             string
		Path             string
		InputFiles       func() []string
		OutputFobidFile  string
		OutputPermitFile string
	}{
		string(azpolicies.PolicyV1): {
			"RAW-STATE",
			"./testdata/permissions-states/create-state",
			func() []string {
				return []string{"input-policy-1.json", "input-policy-2.json"}
			},
			"output-forbid.json",
			"output-permit.json",
		},
	}
	for version, test := range tests {
		testDataVersionPath := test.Path + "/" + version
		cases, _ := os.ReadDir(testDataVersionPath)
		for _, c := range cases {
			name := c.Name()
			if strings.ToLower(name) == ".ds_store" {
				continue
			}
			testDataCasePath := testDataVersionPath + "/" + name
			t.Run(strings.ToUpper(version+"-"+test.Name+"-"+name), func(t *testing.T) {
				assert := assert.New(t)
				permState, _ := newPermissionsState()
				totPermitted, totFobidden := 0, 0
				for _, input := range test.InputFiles() {
					bArray, _ := os.ReadFile(testDataCasePath + "/" + input)
					data := azpolicies.ACPolicy{}
					_ = json.Unmarshal(bArray, &data)
					var err error
					extPermsState, _ := newExtendedPermissionsState(permState)
					err = extPermsState.fobidACPolicyStatements(data.Forbid)
					assert.Nil(err, "wrong result\nshould be nil")
					totPermitted += len(data.Permit)
					err = extPermsState.permitACPolicyStatements(data.Permit)
					assert.Nil(err, "wrong result\nshould be nil")
					totFobidden += len(data.Forbid)
				}

				var err error

				forbidList, _ := permState.GetACForbiddenPermissions()
				err = helperToCompareACPolicyStatementWrappers(testDataCasePath+"/"+test.OutputFobidFile, forbidList)
				assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))

				permitList, _ := permState.GetACPermittedPermissions()
				err = helperToCompareACPolicyStatementWrappers(testDataCasePath+"/"+test.OutputPermitFile, permitList)
				assert.Nil(err, "wrong result\nshould be nil and not%s", spew.Sdump(err))
			})
		}
	}
}

func TestMiscellaneousPermissionsState(t *testing.T) {
	assert := assert.New(t)
	{
		_, err := createACPolicyStatementWrapper(nil)
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
		assert.True(errors.Is(err, azpolicies.ErrPoliciesInvalidDataType), "wrong result\ngot: %sshould be of type ErrFilesJSONSchemaValidation", spew.Sdump(err))
	}
	{
		permState, _ := newPermissionsState()
		extPermsState, _ := newExtendedPermissionsState(permState)
		err := extPermsState.fobidACPolicyStatements(nil)
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be not nil")
	}
	{
		permState, _ := newPermissionsState()
		extPermsState, _ := newExtendedPermissionsState(permState)
		err := extPermsState.permitACPolicyStatements(nil)
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be not nil")
	}
}
