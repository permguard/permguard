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
	languageIdentifier string
	supportedPolicyFileExtensions []string
	supportedSchemaFileNames []string
}

// GetLanguageIdentifier returns the identifier of the language.
func (ls *CedarLanguageSpecification) GetLanguageIdentifier() string {
	return ls.languageIdentifier
}

// GetSupportedPolicyFileExtensions returns the list of supported policy file extensions.
func (ls *CedarLanguageSpecification) GetSupportedPolicyFileExtensions() []string {
	return ls.supportedPolicyFileExtensions
}

// GetSupportedSchemaFileNames returns the list of supported schema file names.
func (ls *CedarLanguageSpecification) GetSupportedSchemaFileNames() []string {
	return ls.supportedSchemaFileNames
}
