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
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azcli "github.com/permguard/permguard/pkg/cli"
)

// outFunc is the function to output the result.
var outFunc = func(ctx *aziclicommon.CliCommandContext, printer azcli.CliPrinter) func(map[string]any, string, any, error) map[string]any {
	return func(out map[string]any, key string, value any, err error) map[string]any {
		if ctx.IsJSONOutput() {
			key = strings.ReplaceAll(key, "-", "_")
		}
		if out == nil {
			out = make(map[string]any)
		}
		out[key] = value
		if ctx.IsTerminalOutput() {
			if err != nil {
				printer.Error(err)
			} else {
				printer.Print(out)
			}
		}
		return out
	}
}

// CreateCommandsForWorkspace creates the workspace commands.
func CreateCommandsForWorkspace(deps azcli.CliDependenciesProvider, v *viper.Viper) []*cobra.Command {
	commands := []*cobra.Command{
		CreateCommandForWorkspaceInit(deps, v),
		CreateCommandForWorkspaceRemote(deps, v),
		CreateCommandForWorkspaceCheckout(deps, v),
		CreateCommandForWorkspaceRepo(deps, v),
		CreateCommandForWorkspaceClone(deps, v),
		CreateCommandForWorkspacePull(deps, v),
		CreateCommandForWorkspaceRefresh(deps, v),
		CreateCommandForWorkspaceValidate(deps, v),
		CreateCommandForWorkspaceObjects(deps, v),
		CreateCommandForWorkspacePlan(deps, v),
		CreateCommandForWorkspaceApply(deps, v),
	}
	return commands
}
