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
	"strings"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azlangcode "github.com/permguard/permguard-abs-language/pkg/permcode"
	aztypes "github.com/permguard/permguard-abs-language/pkg/permcode/types"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azsrlzs "github.com/permguard/permguard/plugin/languages/permyaml/serializers"
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
	objMng      *azlangobjs.ObjectManager
	permCodeMng *azlangcode.PermCodeManager
}

// NewYAMLLanguageAbstraction creates a new YAMLLanguageAbstraction.
func NewYAMLLanguageAbstraction() (*YAMLLanguageAbstraction, error) {
	objMng, err := azlangobjs.NewObjectManager()
	if err != nil {
		return nil, err
	}
	permCodeMng, err := azlangcode.NewPermCodeManager()
	if err != nil {
		return nil, err
	}
	return &YAMLLanguageAbstraction{
		objMng:      objMng,
		permCodeMng: permCodeMng,
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

// CreateCommitObject creates a commit object.
func (abs *YAMLLanguageAbstraction) CreateCommitObject(commit *azlangobjs.Commit) (*azlangobjs.Object, error) {
	return abs.objMng.CreateCommitObject(commit)
}

// GetCommitObject gets a commit object.
func (abs *YAMLLanguageAbstraction) GetCommitObject(obj *azlangobjs.Object) (*azlangobjs.Commit, error) {
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, err
	}
	value, ok := objInfo.GetInstance().(*azlangobjs.Commit)
	if !ok {
		return nil, azerrors.WrapSystemError(azerrors.ErrLanguageFile, "permyaml: invalid object type")
	}
	return value, nil
}

// CreateTreeObject creates a tree object.
func (abs *YAMLLanguageAbstraction) CreateTreeObject(tree *azlangobjs.Tree) (*azlangobjs.Object, error) {
	return abs.objMng.CreateTreeObject(tree)
}

// GetTreeeObject gets a tree object.
func (abs *YAMLLanguageAbstraction) GetTreeeObject(obj *azlangobjs.Object) (*azlangobjs.Tree, error) {
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, err
	}
	value, ok := objInfo.GetInstance().(*azlangobjs.Tree)
	if !ok {
		return nil, azerrors.WrapSystemError(azerrors.ErrLanguageFile, "permyaml: invalid object type")
	}
	return value, nil
}

// CreateMultiSectionsObjects create blobs for multi sections objects.
func (abs *YAMLLanguageAbstraction) CreateMultiSectionsObjects(path string, data []byte) (*azlangobjs.MultiSectionsObject, error) {
	serializer, err := azsrlzs.NewYamlSerializer()
	if err != nil {
		return nil, err
	}
	docs, err := serializer.SplitYAMLDocuments(data)
	if err != nil {
		return azlangobjs.NewMultiSectionsObject(path, 0, err)
	}
	docNumOfSects := len(docs)
	multiSecObj, err := azlangobjs.NewMultiSectionsObject(path, docNumOfSects, nil)
	if err != nil {
		return nil, err
	}
	for i, doc := range docs {
		name, content, codeID, codeType, err := serializer.UnmarshalPermCodeFromPermYaml(doc)
		if err != nil {
			multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", i, err)
			continue
		}
		classInstance, err := abs.permCodeMng.MarshalClass(content, true, true, true)
		if err != nil {
			multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", i, err)
			continue
		}
		langID, langVersionID, langTypeID, err := aztypes.GetClassTypeID(codeType)
		if err != nil {
			multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", i, err)
			continue
		}
		if langID == 0 {
			multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", i, azerrors.WrapSystemError(azerrors.ErrLanguageFile, "permyaml: invalid class type"))
			continue
		}
		header, err := azlangobjs.NewObjectHeader(true, langID, langVersionID, langTypeID)
		if err != nil {
			multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", i, err)
			continue
		}
		obj, err := abs.objMng.CreateBlobObject(header, classInstance)
		if err != nil {
			multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", i, err)
			continue
		}
		objInfo, err := abs.objMng.GetObjectInfo(obj)
		if err != nil {
			return nil, err
		}
		multiSecObj.AddSectionObjectWithParams(obj, objInfo.GetType(), name, codeID, codeType, i, err)
	}
	return multiSecObj, nil
}

// CreateSchemaSectionsObject creates a schema section object.
func (abs *YAMLLanguageAbstraction) CreateSchemaSectionsObject(path string, data []byte) (*azlangobjs.MultiSectionsObject, error) {
	serializer, err := azsrlzs.NewYamlSerializer()
	if err != nil {
		return nil, err
	}
	multiSecObj, err := azlangobjs.NewMultiSectionsObject(path, 1, nil)
	if err != nil {
		return nil, err
	}
	name, content, codeID, codeType, err := serializer.UnmarshalPermCodeFromPermYaml(data)
	if err != nil {
		multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", 0, err)
		return multiSecObj, nil
	}
	classInstance, err := abs.permCodeMng.MarshalClass(content, true, true, true)
	if err != nil {
		multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", 0, err)
		return multiSecObj, nil
	}
	langID, langVersionID, langTypeID, err := aztypes.GetClassTypeID(codeType)
	if err != nil {
		multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", 0, err)
	}
	if langID == 0 {
		multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", 0, azerrors.WrapSystemError(azerrors.ErrLanguageFile, "permyaml: invalid class type"))
		return multiSecObj, nil
	}
	header, err := azlangobjs.NewObjectHeader(true, langID, langVersionID, langTypeID)
	if err != nil {
		multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", 0, err)
		return multiSecObj, nil
	}
	obj, err := abs.objMng.CreateBlobObject(header, classInstance)
	if err != nil {
		multiSecObj.AddSectionObjectWithParams(nil, "", "", "", "", 0, err)
		return multiSecObj, nil
	}
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, err
	}
	multiSecObj.AddSectionObjectWithParams(obj, objInfo.GetType(), name, codeID, codeType, 0, err)
	return multiSecObj, nil
}

// TranslateFromPermCodeToLanguage translates from permcode to language.
func (abs *YAMLLanguageAbstraction) TranslateFromPermCodeToLanguage(obj *azlangobjs.Object) ([]byte, error) {
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, err
	}
	objHeader := objInfo.GetHeader()
	if !objHeader.IsNativeLanguage() {
		return nil, azerrors.WrapSystemError(azerrors.ErrLanguageFile, "permyaml: invalid object type")
	}
	_, _, classType, err := aztypes.GetClassType(objHeader.GetLanguageID(), objHeader.GetLanguageVersionID(), objHeader.GetClassID())
	if err != nil {
		return nil, err
	}
	content := objInfo.GetInstance().([]byte)
	instance, err := abs.permCodeMng.UnmarshalClass(content, classType, false, false, false)
	if err != nil {
		return nil, err
	}
	serializer, err := azsrlzs.NewYamlSerializer()
	var permYamlContent []byte
	var permYamlObj any
	switch classType {
	case aztypes.ClassTypeACPermission:
		permission, ok := instance.Instance.(*aztypes.Permission)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrLanguageFile, "permyaml: invalid object type")
		}
		permYamlObj, err = serializer.ConvertPermissionFromPermCode(permission)
		if err != nil {
			return nil, err
		}
	case aztypes.ClassTypeACPolicy:
		policy, ok := instance.Instance.(*aztypes.Policy)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrLanguageFile, "permyaml: invalid object type")
		}
		permYamlObj, err = serializer.ConvertPolicyFromPermCode(policy)
		if err != nil {
			return nil, err
		}
	case aztypes.ClassTypeSchema:
		schema, ok := instance.Instance.(*aztypes.Schema)
		if !ok {
			return nil, azerrors.WrapSystemError(azerrors.ErrLanguageFile, "permyaml: invalid object type")
		}
		permYamlObj, err = serializer.ConvertSchemaFromPermCode(schema)
		if err != nil {
			return nil, err
		}
	}
	permYamlContent, err = serializer.Marshal(permYamlObj)
	if err != nil {
		return nil, err
	}
	return permYamlContent, nil
}

// CreateLanguageFile combines the blocks for the language.
func (abs *YAMLLanguageAbstraction) CreateLanguageFile(blocks [][]byte) ([]byte, string, error) {
	var sb strings.Builder
	for i, block := range blocks {
		if i > 0 {
			sb.WriteString("\n---\n")
		}
		sb.Write(block)
	}
	return []byte(sb.String()), LanguageFileYml, nil
}
