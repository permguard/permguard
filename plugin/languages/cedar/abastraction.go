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

package cedar

import (
	"strings"

	azlang "github.com/permguard/permguard/pkg/core/languages"
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// LanguageIdentifier defines the identifier for the Cedar language.
	LanguageIdentifier = "cedar"
	// CedarFileExtension specifies the file extension for Cedar language files.
	CedarFileExtension = ".cedar"
	// SchemaFileName specifies the name of the schema definition file.
	SchemaFileName = "schema.json"
)

// CedarLanguageAbstraction is the abstraction for the cedar language.
type CedarLanguageAbstraction struct {
	objMng *azlangobjs.ObjectManager
}

// NewCedarLanguageAbstraction creates a new CedarLanguageAbstraction.
func NewCedarLanguageAbstraction() (*CedarLanguageAbstraction, error) {
	objMng, err := azlangobjs.NewObjectManager()
	if err != nil {
		return nil, err
	}
	return &CedarLanguageAbstraction{
		objMng: objMng,
	}, nil
}

// GetLanguageSpecification returns the specification for the language.
func (abs *CedarLanguageAbstraction)GetLanguageSpecification() azlang.LanguageSpecification {
	return &CedarLanguageSpecification{
		languageIdentifier: LanguageIdentifier,
		supportedPolicyFileExtensions: []string{CedarFileExtension},
		supportedSchemaFileNames: []string{SchemaFileName},
	}
}

// CreateCommitObject creates a commit object.
func (abs *CedarLanguageAbstraction) CreateCommitObject(commit *azlangobjs.Commit) (*azlangobjs.Object, error) {
	return abs.objMng.CreateCommitObject(commit)
}

// GetCommitObject gets a commit object.
func (abs *CedarLanguageAbstraction) GetCommitObject(obj *azlangobjs.Object) (*azlangobjs.Commit, error) {
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, err
	}
	value, ok := objInfo.GetInstance().(*azlangobjs.Commit)
	if !ok {
		return nil, azerrors.WrapSystemError(azerrors.ErrLanguageFile, "cedar: invalid object type")
	}
	return value, nil
}

// CreateTreeObject creates a tree object.
func (abs *CedarLanguageAbstraction) CreateTreeObject(tree *azlangobjs.Tree) (*azlangobjs.Object, error) {
	return abs.objMng.CreateTreeObject(tree)
}

// GetTreeeObject gets a tree object.
func (abs *CedarLanguageAbstraction) GetTreeeObject(obj *azlangobjs.Object) (*azlangobjs.Tree, error) {
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, err
	}
	value, ok := objInfo.GetInstance().(*azlangobjs.Tree)
	if !ok {
		return nil, azerrors.WrapSystemError(azerrors.ErrLanguageFile, "cedar: invalid object type")
	}
	return value, nil
}

// CreateMultiSectionsObjects create blobs for multi sections objects.
func (abs *CedarLanguageAbstraction) CreateMultiSectionsObjects(path string, data []byte) (*azlangobjs.MultiSectionsObject, error) {
	return nil, nil
}

// CreateSchemaSectionsObject creates a schema section object.
func (abs *CedarLanguageAbstraction) CreateSchemaSectionsObject(path string, data []byte) (*azlangobjs.MultiSectionsObject, error) {
	return nil, nil
}

// TranslateFromPermCodeToLanguage translates from permcode to language.
func (abs *CedarLanguageAbstraction) TranslateFromPermCodeToLanguage(obj *azlangobjs.Object) (string, []byte, error) {
	return "", nil, nil
}

// CreateLanguageFile combines the blocks for the language.
func (abs *CedarLanguageAbstraction) CreateLanguageFile(blocks [][]byte) ([]byte, string, error) {
	var sb strings.Builder
	for i, block := range blocks {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.Write(block)
	}
	return []byte(sb.String()), CedarFileExtension, nil
}
