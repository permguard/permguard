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

package cedarlang

const (
	// LanguageName specifies the canonical name of the Cedar language.
	LanguageName = "cedar"

	// LanguageCedar represents the unique identifier for the Cedar language.
	LanguageCedar = "cedar"
	// LanguageCedarID represents the unique identifier for the Cedar language.
	LanguageCedarID = uint32(1)

	// LanguageCedarJSON represents the unique identifier for the JSON-based Cedar language.
	LanguageCedarJSON = "cedar-json"
	// LanguageCedarJSONID represents the unique identifier for the JSON-based Cedar language.
	LanguageCedarJSONID = uint32(2)

	// LanguageSyntaxVersion defines the latest syntax version used by the Cedar language.
	LanguageSyntaxVersion = "0.0"
	// LanguageSyntaxVersionID defines the latest syntax version ID used by the Cedar language.
	LanguageSyntaxVersionID = uint32(0)
	// LanguageSchemaType specifies the schema type for Cedar language.
	LanguageSchemaType = "schema"
	// LanguageSchemaTypeID specifies the schema type ID for Cedar language.
	LanguageSchemaTypeID = uint32(1)
	// LanguagePolicyType specifies the policy type for Cedar language.
	LanguagePolicyType = "policy"
	// LanguagePolicyTypeID specifies the policy type ID for Cedar language.
	LanguagePolicyTypeID = uint32(2)

	// LanguageFileExtension specifies the standard file extension for Cedar language files.
	LanguageFileExtension = ".cedar"
	// LanguageSchemaFileName defines the default filename for the schema definition associated with Cedar.
	LanguageSchemaFileName = "schema.json"
)
