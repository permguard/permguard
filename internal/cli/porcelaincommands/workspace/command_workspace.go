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

package workspace

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
)

// validateArg is the function to validate the arguments.
var validateArg = func(_ *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("requires one argument")
	}
	return nil
}

// finalizeOutput injects verbose details into the output map for JSON verbose mode before printing.
func finalizeOutput(ctx *common.CliCommandContext, output map[string]any) map[string]any {
	if output == nil {
		output = map[string]any{}
	}
	if ctx.IsVerboseJSONOutput() {
		lines := ctx.DrainVerboseLines()
		if len(lines) > 0 {
			output["details"] = lines
		}
	}
	return output
}

// finalizeErrorOutput wraps workspace output and verbose context lines into a nested "details" map for error responses.
// This ensures error JSON has only "error", "causes", and "details" at the top level.
func finalizeErrorOutput(ctx *common.CliCommandContext, output map[string]any) map[string]any {
	details := make(map[string]any)
	for k, v := range output {
		details[k] = v
	}
	if ctx.IsVerboseJSONOutput() {
		if lines := ctx.DrainVerboseLines(); len(lines) > 0 {
			details["context"] = lines
		}
	}
	result := map[string]any{}
	if len(details) > 0 {
		result["details"] = details
	}
	return result
}

// failWithDetails prints an error together with any buffered verbose details and returns ErrCommandSilent.
func failWithDetails(ctx *common.CliCommandContext, printer cli.Printer, err error) error {
	printer.ErrorWithOutput(finalizeErrorOutput(ctx, nil), err)
	return common.ErrCommandSilent
}

// outFunc is the function to output the result.
var outFunc = func(ctx *common.CliCommandContext, printer cli.Printer) common.PrinterOutFunc {
	return func(output map[string]any, key string, value any, err error, newLine bool) map[string]any {
		if ctx.IsJSONOutput() {
			key = strings.ReplaceAll(key, "-", "_")
			if key == "" {
				key = "message"
			}
		}
		if output == nil {
			output = make(map[string]any)
		}
		if key != "" && ctx.IsVerboseTerminalOutput() {
			timestamp := time.Now().Format(time.TimeOnly)
			key = fmt.Sprintf("%s %s", common.TimeStampText(timestamp), common.LogHeaderText(key))
		}
		output[key] = value
		if ctx.IsTerminalOutput() {
			if err != nil {
				printer.Error(err)
			} else {
				if newLine {
					printer.PrintlnMap(output)
				} else {
					printer.PrintMap(output)
				}
			}
		}
		return output
	}
}

// CreateCommandsForWorkspace creates the workspace commands.
func CreateCommandsForWorkspace(deps cli.DependenciesProvider, v *viper.Viper) []*cobra.Command {
	commands := []*cobra.Command{
		CreateCommandForWorkspaceInit(deps, v),
		CreateCommandForWorkspaceRemote(deps, v),
		CreateCommandForWorkspaceCheckout(deps, v),
		CreateCommandForWorkspaceLedger(deps, v),
		CreateCommandForWorkspaceClone(deps, v),
		CreateCommandForWorkspacePull(deps, v),
		CreateCommandForWorkspaceRefresh(deps, v),
		CreateCommandForWorkspaceValidate(deps, v),
		CreateCommandForWorkspaceHistory(deps, v),
		CreateCommandForWorkspaceObjects(deps, v),
		CreateCommandForWorkspacePlan(deps, v),
		CreateCommandForWorkspaceApply(deps, v),
	}
	return commands
}
