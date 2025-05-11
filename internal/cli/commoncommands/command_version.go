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

package commoncommands

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"

	"github.com/permguard/permguard/pkg/cli"
)

const (
	// commandNameForIdentitiesCreate is the command name for identities create.
	commandNameForIdentitiesCreate = "identities-create"
)

// runECommandForCreateIdentity runs the command for creating an identity.
func runECommandForCreateIdentity(deps cli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		version, versionMap := ctx.GetClientVersion()
		if ctx.IsVerbose() {
			versionMap["version"] = version
			printer.PrintlnMap(versionMap)
		} else {
			printer.PrintlnMap(map[string]any{"version": version})
		}
		return nil
	} else if ctx.IsTerminalOutput() {
		version, versionMap := ctx.GetClientVersion()
		if ctx.IsVerbose() {
			versionMap["version"] = version
			printer.PrintlnMap(versionMap)
		} else {
			printer.Println(version)
		}
		return nil
	}
	return nil
}

// CreateCommandForVersion creates a command for version.
func CreateCommandForVersion(deps cli.CliDependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "version",
		Short: "Show the version details",
		Long:  common.BuildCliLongTemplate(`This command shows the version details.`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForCreateIdentity(deps, cmd, v)
		},
	}
	return command
}
