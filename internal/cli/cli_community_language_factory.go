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

package cli

import (
	"fmt"

	"github.com/permguard/permguard/pkg/authz/languages"
	"github.com/permguard/permguard/plugin/languages/cedar"
	"github.com/permguard/permguard/ztauthstar-cedar/pkg/cedarlang"
)

// CommunityLanguageFactory is the factory for the community language.
type CommunityLanguageFactory struct {
	languages map[string]languages.LanguageAbastraction
}

// NewCommunityLanguageFactory creates a new community language factory.
func NewCommunityLanguageFactory() (*CommunityLanguageFactory, error) {
	languageFactory := &CommunityLanguageFactory{
		languages: map[string]languages.LanguageAbastraction{},
	}
	cedarLanguageAbs, err := cedar.NewCedarLanguageAbstraction()
	if err != nil {
		return nil, err
	}
	languageFactory.languages[cedarlang.LanguageName] = cedarLanguageAbs
	return languageFactory, nil
}

// LanguageAbastraction gets the language abstraction for the input language.
func (c *CommunityLanguageFactory) LanguageAbastraction(language, version string) (languages.LanguageAbastraction, error) {
	langAbs, exists := c.languages[language]
	if !exists {
		return nil, fmt.Errorf("cli: invalid language %s with version %s", language, version)
	}
	return langAbs, nil
}
