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
	langregistry "github.com/permguard/permguard/pkg/authz/languages/registry"
	"github.com/permguard/permguard/ztauthstar-cedar/pkg/cedarlang"
)

// NewCedarLanguageDescriptor builds the LanguageDescriptor for the Cedar language plugin.
// It encodes all ID-to-name mappings derived from the cedarlang constants so that the
// workspace manager can resolve uint32 IDs to human-readable strings without holding a
// full language abstraction instance.
func NewCedarLanguageDescriptor() *langregistry.LanguageDescriptor {
	return &langregistry.LanguageDescriptor{
		ID:   cedarlang.LanguageCedarID,
		Name: cedarlang.LanguageCedar,
		VariantNames: map[uint32]string{
			cedarlang.LanguageCedarJSONID: cedarlang.LanguageCedarJSON,
		},
		VersionNames: map[uint32]string{
			cedarlang.LanguageSyntaxVersionID: cedarlang.LanguageSyntaxVersion,
		},
		TypeNames: map[uint32]string{
			cedarlang.LanguageSchemaTypeID: cedarlang.LanguageSchemaType,
			cedarlang.LanguagePolicyTypeID: cedarlang.LanguagePolicyType,
		},
		CodeTypeNames: map[uint32]string{
			cedarlang.LanguageSchemaTypeID: cedarlang.LanguageSchemaType,
			cedarlang.LanguagePolicyTypeID: cedarlang.LanguagePolicyType,
		},
		PluginMode: langregistry.PluginModeLocal,
	}
}
