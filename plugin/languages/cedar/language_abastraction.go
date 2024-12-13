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
	"bytes"
	"strings"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlang "github.com/permguard/permguard/pkg/core/languages"
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
func (abs *CedarLanguageAbstraction) GetLanguageSpecification() azlang.LanguageSpecification {
	return &CedarLanguageSpecification{
		languageIdentifier:            LanguageIdentifier,
		supportedPolicyFileExtensions: []string{CedarFileExtension},
		supportedSchemaFileNames:      []string{SchemaFileName},
	}
}

// CreateCommitObject creates a commit object.
func (abs *CedarLanguageAbstraction) CreateCommitObject(commit *azlangobjs.Commit) (*azlangobjs.Object, error) {
	return abs.objMng.CreateCommitObject(commit)
}

// ConvertObjectToCommit converts an object to a commit.
func (abs *CedarLanguageAbstraction) ConvertObjectToCommit(obj *azlangobjs.Object) (*azlangobjs.Commit, error) {
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

// ConvertObjectToTree converts an object to a tree.
func (abs *CedarLanguageAbstraction) ConvertObjectToTree(obj *azlangobjs.Object) (*azlangobjs.Tree, error) {
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

// CreatePolicyBlobObjects creates multi sections policy blob objects.
func (abs *CedarLanguageAbstraction) CreatePolicyBlobObjects(path string, data []byte) (*azlangobjs.MultiSectionsObject, error) {
	return nil, nil
}

// ReadPolicyBlobObject reads the policy blob object body.
func (abs *CedarLanguageAbstraction) ReadPolicyBlobObject(obj *azlangobjs.Object) (string, []byte, error) {
	return "", nil, nil
}

// CreateMultiPolicyBodyBody creates a multi policy body.
func (abs *CedarLanguageAbstraction) CreateMultiPolicyBody(blocks [][]byte) ([]byte, string, error) {
	var sb strings.Builder
	for i, block := range blocks {
		if i > 0 {
			sb.WriteString("\n")
		}
		sb.Write(block)
	}
	return []byte(sb.String()), CedarFileExtension, nil
}

// CreateSchemaBlobObjects creates multi sections schema blob objects.
func (abs *CedarLanguageAbstraction) CreateSchemaBlobObjects(path string, data []byte) (*azlangobjs.MultiSectionsObject, error) {
	return nil, nil
}

// ReadSchemaBlobObject reads the schema blob object body.
func (abs *CedarLanguageAbstraction) ReadSchemaBlobObject(obj *azlangobjs.Object) (string, []byte, error) {
	return "", nil, nil
}

// CreateSchemaBody creates a schema body.
func (abs *CedarLanguageAbstraction) CreateSchemaBody(blocks [][]byte) ([]byte, string, error) {
	return bytes.Join(blocks, nil), CedarFileExtension, nil
}
