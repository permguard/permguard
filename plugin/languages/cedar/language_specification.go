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

// CedarLanguageSpecification is the specification for the cedar language.
type CedarLanguageSpecification struct {
	language                      string
	languageVersion               string
	languageVersionID             uint32
	frontendLanguage              string
	frontendLanguageID            uint32
	backendLanguage               string
	backendLanguageID             uint32
	supportedPolicyFileExtensions []string
	supportedSchemaFileNames      []string
}

// GetLanguage returns the name of the language.
func (ls *CedarLanguageSpecification) GetLanguage() string {
	return ls.language
}

// GetLanguageVersion returns the language version.
func (ls *CedarLanguageSpecification) GetLanguageVersion() string {
	return ls.languageVersion
}

// GetLanguageVersionID returns the language version ID.
func (ls *CedarLanguageSpecification) GetLanguageVersionID() uint32 {
	return ls.languageVersionID
}

// GetFrontendLanguage returns the name of the language.
func (ls *CedarLanguageSpecification) GetFrontendLanguage() string {
	return ls.frontendLanguage
}

// GetFrontendLanguageID returns the id of the language.
func (ls *CedarLanguageSpecification) GetFrontendLanguageID() uint32 {
	return ls.frontendLanguageID
}

// GetBackendLanguage returns the name of the backend language.
func (ls *CedarLanguageSpecification) GetBackendLanguage() string {
	return ls.backendLanguage
}

// GetBackendLanguageID returns the id of the backend language.
func (ls *CedarLanguageSpecification) GetBackendLanguageID() uint32 {
	return ls.backendLanguageID
}

// GetSupportedPolicyFileExtensions returns the list of supported policy file extensions.
func (ls *CedarLanguageSpecification) GetSupportedPolicyFileExtensions() []string {
	return ls.supportedPolicyFileExtensions
}

// GetSupportedSchemaFileNames returns the list of supported schema file names.
func (ls *CedarLanguageSpecification) GetSupportedSchemaFileNames() []string {
	return ls.supportedSchemaFileNames
}
