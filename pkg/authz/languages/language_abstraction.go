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
	"github.com/permguard/permguard/ztauthstar/pkg/authzen"
	manifests "github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/manifests"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// LanguageAbastraction is the interface for the language abstraction.
type LanguageAbastraction interface {
	// BuildManifest builds the manifest.
	BuildManifest(manifest *manifests.Manifest, template string) (*manifests.Manifest, error)
	// ValidateManifest validates the manifest.
	ValidateManifest(manifest *manifests.Manifest) (bool, error)
	// GetLanguage gets the language name
	GetLanguage() string
	// GetLanguageID gets the language id
	GetLanguageID() uint32
	// GetFrontendLanguage gets fronted language.
	GetFrontendLanguage() string
	// GetFrontendLanguage gets backend language.
	GetBackendLanguage() string
	// GetPolicyFileExtensions gets the policy file extensions.
	GetPolicyFileExtensions() []string
	// CreatePolicyBlobObjects creates multi sections policy blob objects.
	CreatePolicyBlobObjects(mfestLang *manifests.Language, partition string, path string, data []byte) (*objects.MultiSectionsObject, error)
	// CreatePolicyContentBytesBody creates a multi policy content bytes.
	CreatePolicyContentBytes(mfestLang *manifests.Language, blocks [][]byte) ([]byte, string, error)
	// GetSchemaFileNames gets the schema file names.
	GetSchemaFileNames() []string
	// CreateSchemaBlobObjects creates multi sections schema blob objects.
	CreateSchemaBlobObjects(mfestLang *manifests.Language, partition string, path string, data []byte) (*objects.MultiSectionsObject, error)
	// CreateSchemaContentBytes creates a schema content bytes.
	CreateSchemaContentBytes(mfestLang *manifests.Language, blocks []byte) ([]byte, string, error)
	// ConvertBytesToFrontendLanguage converts bytes to the frontend language.
	ConvertBytesToFrontendLanguage(mfestLang *manifests.Language, langID, langVersionID, langTypeID uint32, content []byte) ([]byte, error)
	// AuthorizationCheck checks the authorization.
	AuthorizationCheck(mfestLang *manifests.Language, contextID string, policyStore *authzen.PolicyStore, authzCtx *authzen.AuthorizationModel) (*authzen.AuthorizationDecision, error)
}
