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
	"strings"

	"github.com/fatih/color"
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
// In verbose JSON mode, "details" is always present (at minimum an empty array).
func finalizeOutput(ctx *common.CliCommandContext, output map[string]any) map[string]any {
	if output == nil {
		output = map[string]any{}
	}
	if ctx.IsVerboseJSONOutput() {
		details := ctx.DrainVerboseDetails()
		if details == nil {
			details = []map[string]any{}
		}
		output["details"] = details
	}
	return output
}

// finalizeErrorOutput returns an error-output map with a typed "details" array for verbose JSON mode.
// Error JSON contains only "error", "causes", and (when verbose) "details".
// In verbose JSON mode "details" is always present (at minimum an empty array).
func finalizeErrorOutput(ctx *common.CliCommandContext, _ map[string]any) map[string]any {
	result := map[string]any{}
	if ctx.IsVerboseJSONOutput() {
		details := ctx.DrainVerboseDetails()
		if details == nil {
			details = []map[string]any{}
		}
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
		// In JSON verbose mode, nil-input calls are streaming milestone messages.
		// Buffer them as typed action objects into verboseDetails.
		if ctx.IsVerboseJSONOutput() && output == nil {
			if strVal, ok := value.(string); ok && strVal != "" {
				msg := strings.ToLower(strings.TrimRight(strings.TrimSpace(strVal), "."))
				ctx.AppendVerboseAction(msg)
			}
			return nil
		}
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
			if strVal, ok := value.(string); ok {
				color.HiBlack("%s\n", strVal)
				return output
			}
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
