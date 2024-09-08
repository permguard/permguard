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

package permyaml

import (
	azsrlzs "github.com/permguard/permguard/plugin/languages/permyaml/serializers"
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azlangcode "github.com/permguard/permguard-abs-language/pkg/permcode"
)

const (
	// LanguageName is the name of the permyaml language.
	LanguageName = "permyaml"
	// LanguageFileYml is the yml file extension.
	LanguageFileYml = ".yml"
	// LanguageFileYaml is the yaml file extension.
	LanguageFileYaml = ".yaml"
)

// YAMLLanguageAbstraction is the abstraction for the permyaml language.
type YAMLLanguageAbstraction struct {
	objMng		*azlangobjs.ObjectManager
	permCodeMng *azlangcode.PermCodeManager
}

// NewYAMLLanguageAbstraction creates a new YAMLLanguageAbstraction.
func NewYAMLLanguageAbstraction() (*YAMLLanguageAbstraction, error) {
	return &YAMLLanguageAbstraction{
		objMng: azlangobjs.NewObjectManager(),
		permCodeMng: azlangcode.NewPermCodeManager(),
	}, nil
}

// GetLanguageName returns the name of the language.
func (abs *YAMLLanguageAbstraction) GetLanguageName() string {
	return LanguageName
}

// GetFileExtensions returns the file extensions.
func (abs *YAMLLanguageAbstraction) GetFileExtensions() []string {
	return []string{LanguageFileYml, LanguageFileYaml}
}

// CreateTreeObject creates a tree object.
func (abs *YAMLLanguageAbstraction) CreateTreeObject(tree *azlangobjs.Tree) (*azlangobjs.Object, error) {
	return abs.objMng.CreateTreeObject(tree)
}

// CreateBlobObjects creates blob objects.
func (abs *YAMLLanguageAbstraction) CreateBlobObjects(data []byte) ([]azlangobjs.Object, error) {
	serializer, err := azsrlzs.NewYaml2Json()
	if err != nil {
		return nil, err
	}
	docs, err := serializer.SplitYAMLDocuments(data)
	if err != nil {
		return nil, err
	}
	objs := make([]azlangobjs.Object, 0)
	for _, doc := range docs {
		content, err := serializer.SerializeYAML2JSON(doc)
		if err != nil {
			return nil, err
		}
		obj, err := abs.objMng.CreateBlobObject(content)
		if err != nil {
			return nil, err
		}
		objs = append(objs, *obj)
	}
	return objs, nil
}
