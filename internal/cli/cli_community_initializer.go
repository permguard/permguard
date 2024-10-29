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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliaccounts "github.com/permguard/permguard/internal/cli/porcelaincommands/accounts"
	azicliauthn "github.com/permguard/permguard/internal/cli/porcelaincommands/authn"
	azicliauthz "github.com/permguard/permguard/internal/cli/porcelaincommands/authz"
	azicliconfigs "github.com/permguard/permguard/internal/cli/porcelaincommands/configs"
	azicliwks "github.com/permguard/permguard/internal/cli/porcelaincommands/workspace"
	azcli "github.com/permguard/permguard/pkg/cli"
	azlang "github.com/permguard/permguard/pkg/core/languages"
)

// CommunityCliInitializer  is the community cli initializer.
type CommunityCliInitializer struct{}

// NewCommunityCliInitializer returns a new initializer.
func NewCommunityCliInitializer() (*CommunityCliInitializer, error) {
	return &CommunityCliInitializer{}, nil
}

// GetCliInfo returns the infos of the cli.
func (s *CommunityCliInitializer) GetCliInfo() azcli.CliInfo {
	return azcli.CliInfo{
		Name:  "Community Command Line Interface",
		Use:   "permguard",
		Short: "The official Permguard© Cli",
		Long:  aziclicommon.BuildCliLongTemplate("Permguard is an Open Source Multi-Account and Multi-Tenant Authorization Provider."),
	}
}

// GetCliCommands returns commands.
func (s *CommunityCliInitializer) GetCliCommands(deps azcli.CliDependenciesProvider, v *viper.Viper) ([]*cobra.Command, error) {
	accountsCmd := azicliaccounts.CreateCommandForAccounts(deps, v)
	authnCmd := azicliauthn.CreateCommandForAuthN(deps, v)
	authzCmd := azicliauthz.CreateCommandForAuthZ(deps, v)
	configCmd := azicliconfigs.CreateCommandForConfig(deps, v)
	wksCmds := azicliwks.CreateCommandsForWorkspace(deps, v)
	return append([]*cobra.Command{
		accountsCmd,
		authnCmd,
		authzCmd,
		configCmd,
	}, wksCmds...), nil
}

// GetLanguageFactory returns the language factory.
func (s *CommunityCliInitializer) GetLanguageFactory() (azlang.LanguageFactory, error) {
	return NewCommunityLanguageFactory()
}
