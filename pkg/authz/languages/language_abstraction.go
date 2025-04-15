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
	azauthzen "github.com/permguard/permguard-ztauthstar/pkg/authzen"
	azztasmanifests "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar/authstarmodels/manifests"
	azobjs "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar/authstarmodels/objects"
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
	// BuildManifest builds the manifest.
	BuildManifest(manifest *azztasmanifests.Manifest, template string) (*azztasmanifests.Manifest, error)
	// ValidateManifest validates the manifest.
	ValidateManifest(manifest *azztasmanifests.Manifest) (bool, error)
	// GetLanguageSpecification returns the specification for the language.
	GetLanguageSpecification() LanguageSpecification
	// CreatePolicyBlobObjects creates multi sections policy blob objects.
	CreatePolicyBlobObjects(path string, data []byte) (*azobjs.MultiSectionsObject, error)
	// CreatePolicyContentBytesBody creates a multi policy content bytes.
	CreatePolicyContentBytes(blocks [][]byte) ([]byte, string, error)
	// CreateSchemaBlobObjects creates multi sections schema blob objects.
	CreateSchemaBlobObjects(path string, data []byte) (*azobjs.MultiSectionsObject, error)
	// CreateSchemaContentBytes creates a schema content bytes.
	CreateSchemaContentBytes(blocks []byte) ([]byte, string, error)
	// ConvertBytesToFrontendLanguage converts bytes to the frontend language.
	ConvertBytesToFrontendLanguage(langID, langVersionID, langTypeID uint32, content []byte) ([]byte, error)
	// AuthorizationCheck checks the authorization.
	AuthorizationCheck(contextID string, policyStore *azauthzen.PolicyStore, authzCtx *azauthzen.AuthorizationModel) (*azauthzen.AuthorizationDecision, error)
}
