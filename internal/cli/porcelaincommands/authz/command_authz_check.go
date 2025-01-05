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
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
)

const (
	// commandNameForCheck is the command name for check.
	commandNameForCheck = "check"
)

// runECommandForCheck runs the command for executing check.
func runECommandForCheck(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := aziclicommon.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return aziclicommon.ErrCommandSilent
	}
	handleInputError := func(ctx *aziclicommon.CliCommandContext, printer azcli.CliPrinter, err error, message string) error {
		if ctx.IsTerminalOutput() {
			printer.Println(message)
		}
		if err != nil {
			printer.Error(azerrors.WrapMessageError(err, nil, message))
		} else {
			printer.Error(azerrors.WrapSystemError(azerrors.ErrCliArguments, message))
		}
		return aziclicommon.ErrCommandSilent
	}
	var input *os.File
	if len(args) > 0 {
		jsonPath := filepath.Join(ctx.GetWorkDir(), args[0])
		input, err = os.Open(jsonPath)
		if err != nil {
			return handleInputError(ctx, printer, err, "Invalid input for the authz check.")
		}
		defer input.Close()
	} else {
		input = os.Stdin
	}

	scanner := bufio.NewScanner(input)
	var builder strings.Builder
	for scanner.Scan() {
		builder.WriteString(scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return handleInputError(ctx, printer, err, "Invalid input for the authz check.")
	}
	jsonString := builder.String()
	var authzReq azmodelspdp.AuthorizationCheckRequest
	err = json.Unmarshal([]byte(jsonString), &authzReq)
	if err != nil {
		return handleInputError(ctx, printer, err, "Invalid input for the authz check.")
	}

	pdpTarget := ctx.GetPDPTarget()
	client, err := deps.CreateGrpcPDPClient(pdpTarget)
	if err != nil {
		printer.Error(fmt.Errorf("invalid pdp target %s", pdpTarget))
		return aziclicommon.ErrCommandSilent
	}
	authzResp, err := client.AuthorizationCheck(&authzReq)
	if err != nil {
		printer.Error(err)
		return aziclicommon.ErrCommandSilent
	}
	if ctx.IsTerminalOutput() {
	} else if ctx.IsJSONOutput() {
		var output = map[string]any{}
		output["authorization_check"] = authzResp
		printer.PrintlnMap(output)
	}
	return nil
}

// createCommandForCheck creates a command for executing check.
func createCommandForCheck(deps azcli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "check",
		Short: "Check an authorization request",
		Long: aziclicommon.BuildCliLongTemplate(`This command checks an authorization request.

Examples:
  # check an authorization request
  permguard authz check --appid 268786704340 /path/to/authorization_request.json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCheck(deps, cmd, v, args)
		},
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonApplicationID, 0, "application id")
	v.BindPFlag(azoptions.FlagName(commandNameForCheck, aziclicommon.FlagCommonApplicationID), command.PersistentFlags().Lookup(aziclicommon.FlagCommonApplicationID))

	return command
}
