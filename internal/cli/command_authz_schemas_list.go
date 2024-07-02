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

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclients "github.com/permguard/permguard/internal/agents/clients"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	commandNameForSchemasList = "schemas.list"
)

// runECommandForListSchemas runs the command for creating a schema.
func runECommandForListSchemas(cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := createContextAndPrinter(cmd, v)
	if err != nil {
		color.Red("invalid inputs")
		return ErrCommandSilent
	}
	papTarget := ctx.GetPAPTarget()
	client, err := aziclients.NewGrpcPAPClient(papTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid pap target %s", papTarget))
		return ErrCommandSilent
	}
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForSchema, flagCommonAccountID))
	schemaID := v.GetString(azconfigs.FlagName(commandNameForSchemasList, flagSchemaID))
	schemas, err := client.GetSchemasBy(accountID, schemaID)
	if err != nil {
		printer.Error(err)
		return ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		for _, schema := range schemas {
			output[schema.SchemaID] = schema.RepositoryName
		}
	} else if ctx.IsJSONOutput() {
		output["schema"] = schemas
	}
	printer.Print(output)
	return nil
}

// createCommandForSchemaList creates a command for managing schemalist.
func createCommandForSchemaList(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "list",
		Short: "List schemas",
		Long: `This command lists all the schemas.

Examples:
  # list all schemas for account 301990992055
  permguard authz schemas list --account 301990992055
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForListSchemas(cmd, v)
		},
	}
	command.Flags().String(flagSchemaID, "", "schema id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForSchemasList, flagSchemaID), command.Flags().Lookup(flagSchemaID))
	return command
}
