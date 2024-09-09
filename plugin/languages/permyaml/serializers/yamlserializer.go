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
	"bytes"
	"errors"

	"gopkg.in/yaml.v2"

	aztypes "github.com/permguard/permguard-abs-language/pkg/permcode/types"
)

// YamlSerializer is the YAML serializer.
type YamlSerializer struct {
}

// NewYamlSerializer creates a new YamlSerializer.
func NewYamlSerializer() (*YamlSerializer, error) {
	return &YamlSerializer{}, nil
}

// SplitYAMLDocuments splits a YAML byte array into multiple YAML documents.
func (s *YamlSerializer) SplitYAMLDocuments(data []byte) ([][]byte, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var documents [][]byte
	for {
		var doc interface{}
		err := decoder.Decode(&doc)
		if err != nil {
			break
		}
		docBytes, err := yaml.Marshal(doc)
		if err != nil {
			return nil, err
		}
		documents = append(documents, docBytes)
	}
	return documents, nil
}

// UnmarshalYaml unmarshals a YAML byte array.
func (s *YamlSerializer) UnmarshalYaml(data []byte) (any, error) {
	var tempMap map[string]interface{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&tempMap)
	if err != nil {
		return nil, err
	}
	_, hasPermit := tempMap["permit"]
	_, hasForbid := tempMap["forbid"]
	_, hasActions := tempMap["actions"]
	_, hasResource := tempMap["resource"]
	if hasPermit || hasForbid {
		var perm Permission
		err = yaml.Unmarshal([]byte(data), &perm)
		if err != nil {
			return nil, err
		}
		return &perm, nil
	} else if hasActions || hasResource {
		var policy Policy
		err = yaml.Unmarshal([]byte(data), &policy)
		if err != nil {
			return nil, err
		}
		return &policy, nil
	}
	return nil, errors.New("permyaml: invalid yaml document")
}

// UnmarshalLangType unmarshals a language type.
func (s *YamlSerializer) UnmarshalLangType(data []byte) (string, any, error) {
	instance, err := s.UnmarshalYaml(data)
	if err != nil {
		return "", nil, err
	}
	switch v := instance.(type) {
	case *Permission:
		langPerm := &aztypes.Permission{
			Class: aztypes.Class{
				SyntaxVersion: aztypes.PolicySyntax,
				Type:          aztypes.ClassTypeACPermission,
			},
			Name:   v.Name,
			Permit: v.Permit,
			Forbid: v.Forbid,
		}
		return langPerm.Name, langPerm, nil
	case *Policy:
		langPolicy := &aztypes.Policy{
			Class: aztypes.Class{
				SyntaxVersion: aztypes.PolicySyntax,
				Type:          aztypes.ClassTypeACPermission,
			},
			Name:     v.Name,
			Actions:  make([]aztypes.ARString, 0),
			Resource: aztypes.UURString(v.Resources[0]),
		}
		for _, action := range v.Actions {
			langPolicy.Actions = append(langPolicy.Actions, aztypes.ARString(action))
		}
		return langPolicy.Name, langPolicy, nil
	}
	return "", nil, errors.New("permyaml: invalid yaml document")
}
