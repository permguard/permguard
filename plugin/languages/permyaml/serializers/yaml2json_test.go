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

package serializers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	azcrypto "github.com/permguard/permguard-core/pkg/extensions/crypto"
)

func TestJSONUnmarshaling(t *testing.T) {
	tests := []struct {
		Path string
	}{
		{
			Path: "./testdata/policies",
		},
	}
	for _, test := range tests {
		cases, _ := os.ReadDir(test.Path)
		for _, c := range cases {
			name := c.Name()
			if strings.ToLower(name) == ".ds_store" {
				continue
			}
			casePath := filepath.Join(test.Path, name)
			t.Run(strings.ToUpper(casePath), func(t *testing.T) {
				assert := assert.New(t)
				data, err := os.ReadFile(casePath)
				assert.Nil(err, "error reading file")
				y2j := Yaml2Json{}

				// First iteration: YAML to JSON
				jsonData1, err := y2j.SerializeYAML2JSON(data)
				assert.Nil(err, "error converting YAML to JSON")
				assert.NotNil(jsonData1, "JSON data is nil")
				json1Sha := azcrypto.ComputeSHA1(jsonData1)

				// Second iteration: JSON to YAML
				yamlData2, err := y2j.SerializeJSON2YAML(jsonData1)
				assert.Nil(err, "error converting JSON to YAML")
				assert.NotNil(yamlData2, "YAML data is nil")
				jsonData2, err := y2j.SerializeYAML2JSON(yamlData2)
				assert.Nil(err, "error converting YAML to JSON")
				assert.NotNil(jsonData2, "JSON data is nil")
				json2Sha := azcrypto.ComputeSHA1(jsonData2)

				assert.Equal(json1Sha, json2Sha, "SHA1 hashes are different")
			})
		}
	}
}
