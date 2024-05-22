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

	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	commandNameForSchemasUpdate = "schemas.update"
)

// runECommandForUpdateSchema runs the command for creating a schema.
func runECommandForUpdateSchema(cmd *cobra.Command, v *viper.Viper) error {
	return runECommandForUpsertSchema(cmd, v, commandNameForSchemasUpdate, false)
}

// createCommandForSchemaUpdate creates a command for managing schemaupdate.
func createCommandForSchemaUpdate(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Update a schema",
		Long: `This command update a schema.

Examples:
  # update a schema with name car-rental from file /path/to/app-v1-schema.json for account 301990992055 and schema id b3c67141-df8a-4bbb-ae89-dee7c70d09f4
  permguard authz schemas update --account 301990992055 --schemaid b3c67141-df8a-4bbb-ae89-dee7c70d09f4 --name car-rental --file /path/to/app-v1-schema.json
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForUpdateSchema(cmd, v)
		},
	}
	command.Flags().String(flagSchemaID, "", "schema id")
	v.BindPFlag(azconfigs.FlagName(commandNameForSchemasUpdate, flagSchemaID), command.Flags().Lookup(flagSchemaID))
	command.Flags().StringP(flagCommonFile, flagCommonFileShort, "", "schema file")
	v.BindPFlag(azconfigs.FlagName(commandNameForSchemasUpdate, flagCommonFile), command.Flags().Lookup(flagCommonFile))
	return command
}
