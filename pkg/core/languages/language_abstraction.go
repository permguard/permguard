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

package languages

import (
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
)

// LanguageSpecification is the interface for the language specification.
type LanguageSpecification interface {
	// GetLanguage returns the name of the language.
	GetLanguage() string
	// GetLanguageVersion returns the version of the language.
	GetLanguageVersion() string
	// GetLanguageVersionID returns the id of the language version.
	GetLanguageVersionID() uint32
	// GetFrontendLanguage returns the name of the frontend language.
	GetFrontendLanguage() string
	// GetFrontendLanguage returns the id of the frontend language.
	GetFrontendLanguageID() uint32
	// GetBackendLanguage returns the name of the backend language.
	GetBackendLanguage() string
	// GetBackendLanguageID returns the id of the backend language.
	GetBackendLanguageID() uint32
	// GetSupportedPolicyFileExtensions returns the list of supported policy file extensions.
	GetSupportedPolicyFileExtensions() []string
	// GetSupportedSchemaFileNames returns the list of supported schema file names.
	GetSupportedSchemaFileNames() []string
}

// LanguageAbastraction is the interface for the language abstraction.
type LanguageAbastraction interface {
	// GetLanguageSpecification returns the specification for the language.
	GetLanguageSpecification() LanguageSpecification
	// ReadObjectContentBytes reads the object content bytes.
	ReadObjectContentBytes(obj *azlangobjs.Object) (uint32, []byte, error)
	// CreateCommitObject creates a commit object.
	CreateCommitObject(commit *azlangobjs.Commit) (*azlangobjs.Object, error)
	// ConvertObjectToCommit converts an object to a commit.
	ConvertObjectToCommit(obj *azlangobjs.Object) (*azlangobjs.Commit, error)
	// CreateTreeObject creates a tree object.
	CreateTreeObject(tree *azlangobjs.Tree) (*azlangobjs.Object, error)
	// ConvertObjectToTree converts an object to a tree.
	ConvertObjectToTree(obj *azlangobjs.Object) (*azlangobjs.Tree, error)
	// CreatePolicyBlobObjects creates multi sections policy blob objects.
	CreatePolicyBlobObjects(path string, data []byte) (*azlangobjs.MultiSectionsObject, error)
	// CreateMultiPolicyContentBytesBody creates a multi policy content bytes.
	CreateMultiPolicyContentBytes(blocks [][]byte) ([]byte, string, error)
	// CreateSchemaBlobObjects creates multi sections schema blob objects.
	CreateSchemaBlobObjects(path string, data []byte) (*azlangobjs.MultiSectionsObject, error)
	// CreateSchemaContentBytes creates a schema content bytes.
	CreateSchemaContentBytes(blocks []byte) ([]byte, string, error)
	// ConvertBytesToFrontend converts bytes to the frontend language.
	ConvertBytesToFrontend(langID, langVersionID, langTypeID uint32, content []byte) ([]byte, error)
}
