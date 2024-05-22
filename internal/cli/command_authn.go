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
)

// runECommandForAuthN runs the command for managing authn.
func runECommandForAuthN(cmd *cobra.Command) error {
	return cmd.Help()
}

// createCommandForAuthN for managing authn.
func createCommandForAuthN(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "authn",
		Short: "Manage Tenants and Identities",
		Long:  `This command manage tenants and identities.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForAuthN(cmd)
		},
	}
	command.AddCommand(createCommandForTenants(v))
	command.AddCommand(createCommandForIdentitySources(v))
	command.AddCommand(createCommandForIdentities(v))
	return command
}
