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
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to check the authorization request.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliOperation, message, err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	var input *os.File
	if len(args) > 0 {
		jsonPath := filepath.Join(ctx.GetWorkDir(), args[0])
		input, err = os.Open(jsonPath)
		if err != nil {
			return handleInputError(ctx, printer, err, "invalid input for the authz check.")
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
	var authzReq azmodelspdp.AuthorizationCheckWithDefaultsRequest
	err = json.Unmarshal([]byte(jsonString), &authzReq)
	if err != nil {
		return handleInputError(ctx, printer, err, "Invalid input for the authz check.")
	}

	pdpTarget, err := ctx.GetPDPTarget()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to check the authorization request.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, "failed to check the authorization request.", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	client, err := deps.CreateGrpcPDPClient(pdpTarget)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to check the authorization request.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, "failed to check the authorization request.", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	authzResp, err := client.AuthorizationCheck(&authzReq)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to check the authorization request.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			sysErr := azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliArguments, "failed to check the authorization request.", err)
			printer.Error(sysErr)
		}
		return aziclicommon.ErrCommandSilent
	}
	if ctx.IsTerminalOutput() {
		decision := authzResp.Decision
		printer.Println(fmt.Sprintf("Authorization check response: %v", aziclicommon.BoolText(decision)))
		if !decision {
			contextID := authzResp.Context.ID
			if len(contextID) == 0 {
				contextID = "none"
			}
			printer.Println(fmt.Sprintf("%s: %s", aziclicommon.KeywordText("Context ID"), aziclicommon.CreateText(contextID)))
			if authzResp.Context.ReasonAdmin != nil {
				printer.Println(fmt.Sprintf("  %s: Error: %s - %s ", aziclicommon.KeywordText("Reason Admin"), aziclicommon.IDText(authzResp.Context.ReasonAdmin.Code), authzResp.Context.ReasonAdmin.Message))
			}
			if authzResp.Context.ReasonUser != nil {
				printer.Println(fmt.Sprintf("  %s: Error: %s - %s ", aziclicommon.KeywordText("Reason User"), aziclicommon.IDText(authzResp.Context.ReasonUser.Code), authzResp.Context.ReasonUser.Message))
			}
			if len(authzResp.Evaluations) > 0 {
				printer.Println("Evaluations:")
				for _, eval := range authzResp.Evaluations {
					contextID := eval.Context.ID
					if len(contextID) == 0 {
						contextID = "none"
					}
					requestID := eval.RequestID
					if len(requestID) == 0 {
						requestID = "none"
					}
					printer.Println(fmt.Sprintf("  - %s: %s, %s: %s, %s: %v", aziclicommon.KeywordText("Request ID"), aziclicommon.CreateText(requestID), aziclicommon.KeywordText("Context ID"), aziclicommon.CreateText(contextID), aziclicommon.KeywordText("Decision"), eval.Decision))
					if eval.Context.ReasonAdmin != nil {
						printer.Println(fmt.Sprintf("    - %s: Error: %s - %s ", aziclicommon.KeywordText("Reason Admin"), aziclicommon.IDText(eval.Context.ReasonAdmin.Code), eval.Context.ReasonAdmin.Message))
					}
					if eval.Context.ReasonUser != nil {
						printer.Println(fmt.Sprintf("    - %s: Error: %s - %s ", aziclicommon.KeywordText("Reason User"), aziclicommon.IDText(eval.Context.ReasonUser.Code), eval.Context.ReasonUser.Message))
					}
				}
			}
		}
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
  permguard authz check --zoneid 273165098782 /path/to/authorization_request.json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCheck(deps, cmd, v, args)
		},
	}

	command.PersistentFlags().Int64(aziclicommon.FlagCommonZoneID, 0, "zone id")
	v.BindPFlag(azoptions.FlagName(commandNameForCheck, aziclicommon.FlagCommonZoneID), command.PersistentFlags().Lookup(aziclicommon.FlagCommonZoneID))

	return command
}
