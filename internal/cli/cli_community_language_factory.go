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

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlang "github.com/permguard/permguard/pkg/core/languages"
	azplangcedar "github.com/permguard/permguard/plugin/languages/cedar"
)

// CommunityLanguageFactory is the factory for the community language.
type CommunityLanguageFactory struct {
}

// NewCommunityLanguageFactory creates a new community language factory.
func NewCommunityLanguageFactory() (*CommunityLanguageFactory, error) {
	return &CommunityLanguageFactory{}, nil
}

// CreateLanguageAbastraction creates a language abstraction.
func (c *CommunityLanguageFactory) CreateLanguageAbastraction(language string) (azlang.LanguageAbastraction, error) {
	switch language {
	case azplangcedar.LanguageName:
		return azplangcedar.NewCedarLanguageAbstraction()
	default:
		return nil, azerrors.WrapSystemError(azerrors.ErrConfigurationGeneric, fmt.Sprintf("cli: %s is an invalid language", language))
	}
}
