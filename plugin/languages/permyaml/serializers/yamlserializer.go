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

	"gopkg.in/yaml.v2"

	aztypes "github.com/permguard/permguard-abs-language/pkg/permcode/types"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	errFileMessage   = "permyaml: invalid permyaml file. please check the syntax and ensure it adheres to the permguard specification."
	errSyntaxMessage = "permyaml: invalid permyaml syntax. please check the syntax and ensure it adheres to the permguard specification."
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
		var doc any
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
	var tempMap map[string]any
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&tempMap)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrLanguageFile, errFileMessage)
	}
	_, hasPermit := tempMap["permit"]
	_, hasForbid := tempMap["forbid"]
	_, hasActions := tempMap["actions"]
	_, hasResource := tempMap["resource"]
	_, hasDomains := tempMap["domains"]
	if hasPermit || hasForbid {
		var perm Permission
		err = yaml.Unmarshal([]byte(data), &perm)
		if err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrLanguageSyntax, errSyntaxMessage)
		}
		return &perm, nil
	} else if hasActions || hasResource {
		var policy Policy
		err = yaml.Unmarshal([]byte(data), &policy)
		if err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrLanguageSyntax, errSyntaxMessage)
		}
		return &policy, nil
	} else if hasDomains {
		var schema aztypes.Schema
		err = yaml.Unmarshal([]byte(data), &schema)
		if err != nil {
			return nil, azerrors.WrapSystemError(azerrors.ErrLanguageSyntax, errSyntaxMessage)
		}
		return &schema, nil
	}
	return nil, azerrors.WrapSystemError(azerrors.ErrLanguageSyntax, errSyntaxMessage)
}

// UnmarshalLangType unmarshals a language type.
func (s *YamlSerializer) UnmarshalLangType(data []byte) (string, any, string, string, error) {
	instance, err := s.UnmarshalYaml(data)
	if err != nil {
		return "", nil, "", "", err
	}
	switch v := instance.(type) {
	case *Permission:
		langPerm := &aztypes.Permission{
			Class: aztypes.Class{
				SyntaxVersion: aztypes.PermCodeSyntax,
				Type:          aztypes.ClassTypeACPermission,
			},
			Name:   v.Name,
			Permit: v.Permit,
			Forbid: v.Forbid,
		}
		return langPerm.Name, langPerm, langPerm.Name, aztypes.ClassTypeACPermission, nil
	case *Policy:
		langPolicy := &aztypes.Policy{
			Class: aztypes.Class{
				SyntaxVersion: aztypes.PermCodeSyntax,
				Type:          aztypes.ClassTypeACPolicy,
			},
			Name:     v.Name,
			Actions:  make([]aztypes.ARString, 0),
			Resource: aztypes.UURString(v.Resources[0]),
		}
		for _, action := range v.Actions {
			langPolicy.Actions = append(langPolicy.Actions, aztypes.ARString(action))
		}
		return langPolicy.Name, langPolicy, langPolicy.Name, aztypes.ClassTypeACPolicy, nil
	case *aztypes.Schema:
		v.SyntaxVersion = aztypes.PermCodeSyntax
		v.Type = aztypes.ClassTypeSchema
		return aztypes.ClassTypeSchema, v, aztypes.ClassTypeSchema, aztypes.ClassTypeSchema, nil
	}
	return "", nil, "", "", azerrors.WrapSystemError(azerrors.ErrLanguageFile, errFileMessage)
}
