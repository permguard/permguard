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

	azconfigs "github.com/permguard/permguard/pkg/configs"
	azcopier "github.com/permguard/permguard/pkg/extensions/copier"
)

const (
	commandNameForSchemaValidate = "schema.validate"
)

// runECommandForValidateSchema run the command to validate a schema.
func runECommandForValidateSchema(cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := createContextAndPrinter(cmd, v)
	if err != nil {
		color.Red("invalid inputs")
		return ErrCommandSilent
	}
	file := v.GetString(azconfigs.FlagName(commandNameForSchemaValidate, flagCommonFile))
	schemadomains, err := loadSchemaDomainsFromFile(file, printer)
	if err != nil {
		return err
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		for _, domain := range schemadomains.Domains {
			resourceMap := map[string]any{}
			output[domain.Name] = resourceMap
			for _, resource := range domain.Resources {
				actions := []string{}
				for _, action := range resource.Actions {
					actions = append(actions, action.Name)
				}
				resourceMap[resource.Name] = actions
			}
		}
	} else if ctx.IsJSONOutput() {
		dMap, err := azcopier.ConvertStructToMap(schemadomains)
		if err != nil {
			printer.Error(fmt.Sprintf("invalid schema file %s", file), err)
			return ErrCommandSilent
		}
		output["domains"] = dMap
	}
	printer.Print(output)
	return nil
}

// createCommandForSchemaValidate validate a schema.
func createCommandForSchemaValidate(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "validate",
		Short: "Validate a schema",
		Long: `This command validate a schema.

Examples:
  # validate the schema file /path/to/app-v1-schema.json
  permguard schema validate --file /path/to/app-v1-schema.json
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForValidateSchema(cmd, v)
		},
	}
	command.Flags().StringP(flagCommonFile, flagCommonFileShort, "", "schema file")
	v.BindPFlag(azconfigs.FlagName(commandNameForSchemaValidate, flagCommonFile), command.Flags().Lookup(flagCommonFile))
	return command
}
