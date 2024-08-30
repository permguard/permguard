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

package authn

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/commands/common"
	azcli "github.com/permguard/permguard/pkg/cli"
)

// runECommandForAuthN runs the command for managing authn.
func runECommandForAuthN(cmd *cobra.Command) error {
	return cmd.Help()
}

// CreateCommandForAuthN for managing authn.
func CreateCommandForAuthN(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "authn",
		Short: "Manage tenants and identities on the remote server",
		Long:  aziclicommon.BuildCliLongTemplate(`This command enables managament of tenants and identities on the remote server.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForAuthN(cmd)
		},
	}
	command.AddCommand(createCommandForTenants(deps, v))
	command.AddCommand(createCommandForIdentitySources(deps, v))
	command.AddCommand(createCommandForIdentities(deps, v))
	return command
}
