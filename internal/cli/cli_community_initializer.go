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

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/porcelaincommands/authn"
	"github.com/permguard/permguard/internal/cli/porcelaincommands/authz"
	"github.com/permguard/permguard/internal/cli/porcelaincommands/configs"
	"github.com/permguard/permguard/internal/cli/porcelaincommands/workspace"
	"github.com/permguard/permguard/internal/cli/porcelaincommands/zones"
	"github.com/permguard/permguard/pkg/authz/languages"
	"github.com/permguard/permguard/pkg/cli"
)

// CommunityCliInitializer  is the community cli initializer.
type CommunityCliInitializer struct{}

// NewCommunityCliInitializer returns a new initializer.
func NewCommunityCliInitializer() (*CommunityCliInitializer, error) {
	return &CommunityCliInitializer{}, nil
}

// CliInfo returns the infos of the cli.
func (s *CommunityCliInitializer) CliInfo() cli.CliInfo {
	return cli.CliInfo{
		Name:  "Community Command Line Interface",
		Use:   "permguard",
		Short: "The official Permguard© Cli",
		Long:  common.BuildCliLongTemplate("Permguard is an Open Source Multi-Zone, Multi-Tenant, ZTAuth* Provider."),
	}
}

// CliCommands returns commands.
func (s *CommunityCliInitializer) CliCommands(deps cli.CliDependenciesProvider, v *viper.Viper) ([]*cobra.Command, error) {
	zonesCmd := zones.CreateCommandForZones(deps, v)
	authnCmd := authn.CreateCommandForAuthN(deps, v)
	authzCmd := authz.CreateCommandForAuthZ(deps, v)
	configCmd := configs.CreateCommandForConfig(deps, v)
	wksCmds := workspace.CreateCommandsForWorkspace(deps, v)
	return append([]*cobra.Command{
		zonesCmd,
		authnCmd,
		authzCmd,
		configCmd,
	}, wksCmds...), nil
}

// LanguageFactory returns the language factory.
func (s *CommunityCliInitializer) LanguageFactory() (languages.LanguageFactory, error) {
	return NewCommunityLanguageFactory()
}
