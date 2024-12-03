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
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	errFileMessage   = "cedar: invalid cedar file. please check the syntax and ensure it adheres to the permguard specification."
	errSyntaxMessage = "cedar: invalid cedar syntax. please check the syntax and ensure it adheres to the permguard specification."
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

// UnmarshalCedar unmarshals to a cedar object.
func (s *YamlSerializer) UnmarshalCedar(data []byte) (any, error) {
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

// UnmarshalPermCodeFromCedar unmarshals to a permcode object from a cedar content.
func (s *YamlSerializer) UnmarshalPermCodeFromCedar(data []byte) (string, any, string, string, error) {
	instance, err := s.UnmarshalCedar(data)
	if err != nil {
		return "", nil, "", "", err
	}
	switch v := instance.(type) {
	case *Permission:
		langPerm := &aztypes.Permission{
			Class: aztypes.Class{
				SyntaxVersion: aztypes.PermCodeSyntaxLatest,
				Type:          aztypes.ClassTypeACPermission,
			},
			Name:   v.Name,
			Permit: v.Permit,
			Forbid: v.Forbid,
		}
		return langPerm.Name, langPerm, langPerm.Name, aztypes.ClassTypeACPermission, nil
	case *Policy:
		resource := ""
		if len(v.Resources) > 0 {
			resource = v.Resources[0]
		}
		langPolicy := &aztypes.Policy{
			Class: aztypes.Class{
				SyntaxVersion: aztypes.PermCodeSyntaxLatest,
				Type:          aztypes.ClassTypeACPolicy,
			},
			Name:     v.Name,
			Actions:  make([]aztypes.ARString, 0),
			Resource: aztypes.UURString(resource),
		}
		for _, action := range v.Actions {
			langPolicy.Actions = append(langPolicy.Actions, aztypes.ARString(action))
		}
		return langPolicy.Name, langPolicy, langPolicy.Name, aztypes.ClassTypeACPolicy, nil
	case *aztypes.Schema:
		v.SyntaxVersion = aztypes.PermCodeSyntaxLatest
		v.Type = aztypes.ClassTypeSchema
		return aztypes.ClassTypeSchema, v, aztypes.ClassTypeSchema, aztypes.ClassTypeSchema, nil
	}
	return "", nil, "", "", azerrors.WrapSystemError(azerrors.ErrLanguageFile, errFileMessage)
}

// Marshal marshals data to a byte array.
func (s *YamlSerializer) Marshal(data any) ([]byte, error) {
	return yaml.Marshal(data)
}

// Unmarshal unmarshals data to an object.
func (s *YamlSerializer) Unmarshal(data []byte) (any, error) {
	var result any
	err := yaml.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ConvertSchemaFromPermCode converts a schema from a permcode object.
func (s *YamlSerializer) ConvertSchemaFromPermCode(schema *aztypes.Schema) (*Schema, error) {
	if schema == nil {
		return nil, errors.New("cedar: schema is nil")
	}

	sch := &Schema{
		Domains: make([]Domain, 0),
	}
	for _, domain := range schema.Domains {
		dom := Domain{
			Name:        domain.Name,
			Description: domain.Description,
			Resources:   make([]DomainResource, 0),
		}
		for _, resource := range domain.Resources {
			res := DomainResource{
				Name:    resource.Name,
				Actions: make([]DomainAction, 0),
			}
			for _, action := range resource.Actions {
				act := DomainAction{
					Name:        action.Name,
					Description: action.Description,
				}
				res.Actions = append(res.Actions, act)
			}
			dom.Resources = append(dom.Resources, res)
		}
		sch.Domains = append(sch.Domains, dom)
	}
	return sch, nil
}

// ConvertPermissionFromPermCode converts a permission from a permcode object.
func (s *YamlSerializer) ConvertPermissionFromPermCode(permission *aztypes.Permission) (*Permission, error) {
	if permission == nil {
		return nil, errors.New("cedar: permission is nil")
	}

	perm := &Permission{
		Name:   permission.Name,
		Permit: permission.Permit,
		Forbid: permission.Forbid,
	}
	return perm, nil
}

// ConvertPolicyFromPermCode converts a policy from a permcode object.
func (s *YamlSerializer) ConvertPolicyFromPermCode(policy *aztypes.Policy) (*Policy, error) {
	if policy == nil {
		return nil, errors.New("cedar: policy is nil")
	}

	pol := &Policy{
		Name:      policy.Name,
		Actions:   make([]string, 0),
		Resources: make([]string, 0),
	}
	for _, action := range policy.Actions {
		pol.Actions = append(pol.Actions, string(action))
	}
	pol.Resources = append(pol.Resources, string(policy.Resource))
	return pol, nil
}
