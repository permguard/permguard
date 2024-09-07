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
	"encoding/json"

	"gopkg.in/yaml.v2"
)

type Policy struct {
	Name      string   `yaml:"name"`
	Actions   []string `yaml:"actions"`
	Resources []string `yaml:"resources"`
}

// Yaml2Json is a serializer that converts YAML to JSON.
type Yaml2Json struct {
}

// SerializeYAML2JSON converts a YAML byte array to a JSON byte array.
func (s *Yaml2Json) SerializeYAML2JSON(data []byte) ([]byte, error) {
	var policy Policy
	err := yaml.Unmarshal(data, &policy)
	if err != nil {
		return nil, err
	}
	jsonData, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	return jsonData, nil
}

// SerializeJSON2YAML converts a JSON byte array to a YAML byte array.
func (s *Yaml2Json) SerializeJSON2YAML(data []byte) ([]byte, error) {
	var policy Policy
	err := json.Unmarshal(data, &policy)
	if err != nil {
		return nil, err
	}
	yamlData, err := yaml.Marshal(policy)
	if err != nil {
		return nil, err
	}
	return yamlData, nil
}
