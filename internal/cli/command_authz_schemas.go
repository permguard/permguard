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
	"errors"
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclients "github.com/permguard/permguard/internal/agents/clients"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
	azfiles "github.com/permguard/permguard/pkg/extensions/files"
)

const (
	commandNameForSchema = "schema"
	flagSchemaID         = "schemaid"
)

// loadSchemaDomainsFromFile loads schema domains from a file.
func loadSchemaDomainsFromFile(file string, printer *azcli.CliPrinter) (*azmodels.SchemaDomains, error) {
	var schemadomains *azmodels.SchemaDomains
	err := azfiles.UnmarshalJSONYamlFile(file, &schemadomains)
	if err != nil {
		printer.Error(fmt.Sprintf("file %s is not a valid schema", file), err)
		return nil, ErrCommandSilent
	}
	if isValid, err := schemadomains.Validate(); err != nil || !isValid {
		if err == nil {
			err = errors.New("undefined error")
		}
		printer.Error(fmt.Sprintf("file %s is not a valid schema", file), err)
		return nil, ErrCommandSilent
	}
	return schemadomains, nil
}

// runECommandForCreateSchema runs the command for creating a schema.
func runECommandForUpsertSchema(cmd *cobra.Command, v *viper.Viper, flagPrefix string, isCreate bool) error {
	ctx, printer, err := createContextAndPrinter(cmd, v)
	if err != nil {
		color.Red("invalid inputs")
		return ErrCommandSilent
	}
	papTarget := ctx.GetPAPTarget()
	client, err := aziclients.NewGrpcPAPClient(papTarget)
	if err != nil {
		printer.Error(fmt.Sprintf("invalid pap target %s", papTarget), err)
		return ErrCommandSilent
	}
	accountID := v.GetInt64(azconfigs.FlagName(commandNameForSchema, flagCommonAccountID))
	file := v.GetString(azconfigs.FlagName(flagPrefix, flagCommonFile))
	schemadomains, err := loadSchemaDomainsFromFile(file, printer)
	if err != nil {
		return err
	}
	schema := &azmodels.Schema{
		AccountID:     accountID,
		SchemaDomains: schemadomains,
	}
	if isCreate {
		return fmt.Errorf("cli: create is not implemented")
	} else {
		schemaID := v.GetString(azconfigs.FlagName(flagPrefix, flagSchemaID))
		schema.SchemaID = schemaID
		schema, err = client.UpdateSchema(schema)
	}
	if err != nil {
		printer.Error("operation cannot be completed", err)
		return ErrCommandSilent
	}
	output := map[string]any{}
	if ctx.IsTerminalOutput() {
		output[schema.SchemaID] = schema.RepositoryName
	} else if ctx.IsJSONOutput() {
		output["schema"] = []*azmodels.Schema{schema}
	}
	printer.Print(output)
	return nil
}

// runECommandForSchemas runs the command for managing schemas.
func runECommandForSchemas(cmd *cobra.Command, args []string) error {
	return cmd.Help()
}

// createCommandForSchemas creates a command for managing schemas.
func createCommandForSchemas(v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "schemas",
		Short: "Manage Schemas",
		Long:  `This command manages schemas.`,
		RunE:  runECommandForSchemas,
	}

	command.PersistentFlags().Int64(flagCommonAccountID, 0, "account id filter")
	v.BindPFlag(azconfigs.FlagName(commandNameForSchema, flagCommonAccountID), command.PersistentFlags().Lookup(flagCommonAccountID))

	command.AddCommand(createCommandForSchemaValidate(v))
	command.AddCommand(createCommandForSchemaUpdate(v))
	command.AddCommand(createCommandForSchemaList(v))
	return command
}
