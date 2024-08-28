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

package authz

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
)

// runECommandForAuthZ runs the command for managing authz.
func runECommandForAuthZ(cmd *cobra.Command) error {
	return cmd.Help()
}

// CreateCommandForAuthZ for managing authz.
func CreateCommandForAuthZ(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "authz",
		Short: "Manage Repositories",
		Long:  aziclicommon.BuildCliLongTemplate(`This command enables managament of repositories.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForAuthZ(cmd)
		},
	}
	command.AddCommand(createCommandForRepositories(deps, v))
	return command
}
