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

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
)

// validateArg is the function to validate the arguments.
var validateArg = func(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("requires one argument")
	}
	return nil
}

// outFunc is the function to output the result.
var outFunc = func(ctx *aziclicommon.CliCommandContext, printer azcli.CliPrinter) aziclicommon.PrinterOutFunc {
	return func(output map[string]any, key string, value any, err error, newLine bool) map[string]any {
		if ctx.IsJSONOutput() {
			key = strings.ReplaceAll(key, "-", "_")
		}
		if output == nil {
			output = make(map[string]any)
		}
		if key != "" && ctx.IsVerboseTerminalOutput() {
			timestamp := time.Now().Format(time.TimeOnly)
			key = fmt.Sprintf("%s %s", aziclicommon.TimeStampText(timestamp), aziclicommon.LogHeaderText(key))
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
func CreateCommandsForWorkspace(deps azcli.CliDependenciesProvider, v *viper.Viper) []*cobra.Command {
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
