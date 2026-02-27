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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
	"github.com/permguard/permguard/pkg/transport/models/pdp"
)

const (
	// commandNameForCheck is the command name for check.
	commandNameForCheck = "check"
)

// runECommandForCheck runs the command for executing check.
func runECommandForCheck(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper, args []string) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	handleInputError := func(ctx *common.CliCommandContext, printer cli.Printer, err error, message string) error {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to check the authorization request.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(fmt.Errorf("cli: %s", message), err))
		}
		return common.ErrCommandSilent
	}
	var input *os.File
	if len(args) > 0 {
		jsonPath := filepath.Join(ctx.WorkDir(), args[0])
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
	if err2 := scanner.Err(); err2 != nil {
		return handleInputError(ctx, printer, err2, "Invalid input for the authz check.")
	}
	jsonString := builder.String()
	var authzReq pdp.AuthorizationCheckWithDefaultsRequest
	err = json.Unmarshal([]byte(jsonString), &authzReq)
	if err != nil {
		return handleInputError(ctx, printer, err, "Invalid input for the authz check.")
	}

	pdpEndpoint, err := ctx.PDPEndpoint()
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to check the authorization request.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: storage: failed to check the authorization request"), err))
		}
		return common.ErrCommandSilent
	}
	client, err := deps.CreateGrpcPDPClient(pdpEndpoint)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to check the authorization request.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: storage: failed to check the authorization request"), err))
		}
		return common.ErrCommandSilent
	}
	authzResp, err := client.AuthorizationCheck(&authzReq)
	if err != nil {
		if ctx.IsNotVerboseTerminalOutput() {
			printer.Println("Failed to check the authorization request.")
		}
		if ctx.IsVerboseTerminalOutput() || ctx.IsJSONOutput() {
			printer.Error(errors.Join(errors.New("cli: storage: failed to check the authorization request"), err))
		}
		return common.ErrCommandSilent
	}
	if ctx.IsTerminalOutput() {
		decision := authzResp.Decision
		printer.Println(fmt.Sprintf("Authorization check response: %v", common.BoolText(decision)))
		if authzReq.RequestID != "" {
			printer.Println(fmt.Sprintf("%s: %s", common.KeywordText("Request ID"), common.CreateText(authzReq.RequestID)))
		}
		if !decision {
			contextID := "none"
			if authzResp.Context != nil && len(authzResp.Context.ID) > 0 {
				contextID = authzResp.Context.ID
			}
			printer.Println(fmt.Sprintf("%s: %s", common.KeywordText("Context ID"), common.CreateText(contextID)))
			if authzResp.Context != nil {
				if authzResp.Context.ReasonAdmin != nil {
					printer.Println(fmt.Sprintf("  %s: Error: %s - %s ", common.KeywordText("Reason Admin"), common.IDText(authzResp.Context.ReasonAdmin.Code), authzResp.Context.ReasonAdmin.Message))
				}
				if authzResp.Context.ReasonUser != nil {
					printer.Println(fmt.Sprintf("  %s: Error: %s - %s ", common.KeywordText("Reason User"), common.IDText(authzResp.Context.ReasonUser.Code), authzResp.Context.ReasonUser.Message))
				}
			}
			if len(authzResp.Evaluations) > 0 {
				printer.Println("Evaluations:")
				for _, eval := range authzResp.Evaluations {
					contextID := "none"
					if eval.Context != nil && len(eval.Context.ID) > 0 {
						contextID = eval.Context.ID
					}
					requestID := eval.RequestID
					if len(requestID) == 0 {
						requestID = "none"
					}
					printer.Println(fmt.Sprintf("  - %s: %s, %s: %s, %s: %v", common.KeywordText("Request ID"), common.CreateText(requestID), common.KeywordText("Context ID"), common.CreateText(contextID), common.KeywordText("Decision"), eval.Decision))
					if eval.Context != nil {
						if eval.Context.ReasonAdmin != nil {
							printer.Println(fmt.Sprintf("    - %s: Error: %s - %s ", common.KeywordText("Reason Admin"), common.IDText(eval.Context.ReasonAdmin.Code), eval.Context.ReasonAdmin.Message))
						}
						if eval.Context.ReasonUser != nil {
							printer.Println(fmt.Sprintf("    - %s: Error: %s - %s ", common.KeywordText("Reason User"), common.IDText(eval.Context.ReasonUser.Code), eval.Context.ReasonUser.Message))
						}
					}
				}
			}
		}
	} else if ctx.IsJSONOutput() {
		output := map[string]any{}
		output["authorization_check"] = authzResp
		printer.PrintlnMap(output)
	}
	return nil
}

// createCommandForCheck creates a command for executing check.
func createCommandForCheck(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "check",
		Short: "Check an authorization request",
		Long: common.BuildCliLongTemplate(`This command checks an authorization request.

Examples:
  # check an authorization request
  permguard authz check --zone-id 273165098782 /path/to/authorization_request.json
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCheck(deps, cmd, v, args)
		},
	}

	command.PersistentFlags().Int64(common.FlagCommonZoneID, 0, "zone id")
	_ = v.BindPFlag(options.FlagName(commandNameForCheck, common.FlagCommonZoneID), command.PersistentFlags().Lookup(common.FlagCommonZoneID))

	return command
}
