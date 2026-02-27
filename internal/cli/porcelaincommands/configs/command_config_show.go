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

package configs

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/cli"
)

// runECommandForConfigShow runs the command for showing the current config.
func runECommandForConfigShow(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	zapEndpoint, err := ctx.ZAPEndpoint()
	if err != nil {
		zapEndpoint = "not set"
	}
	papEndpoint, err := ctx.PAPEndpoint()
	if err != nil {
		papEndpoint = "not set"
	}
	pdpEndpoint, err := ctx.PDPEndpoint()
	if err != nil {
		pdpEndpoint = "not set"
	}
	if ctx.IsTerminalOutput() {
		printer.Println(fmt.Sprintf("zap-endpoint: %s", zapEndpoint))
		printer.Println(fmt.Sprintf("pap-endpoint: %s", papEndpoint))
		printer.Println(fmt.Sprintf("pdp-endpoint: %s", pdpEndpoint))
	} else if ctx.IsJSONOutput() {
		output := map[string]any{
			"zap_endpoint": zapEndpoint,
			"pap_endpoint": papEndpoint,
			"pdp_endpoint": pdpEndpoint,
		}
		printer.PrintlnMap(output)
	}
	return nil
}

// createCommandForConfigShow creates the command for showing the current CLI configuration.
func createCommandForConfigShow(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "show",
		Short: "Show current CLI configuration",
		Long:  common.BuildCliLongTemplate(`This command shows the current CLI configuration.`),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runECommandForConfigShow(deps, cmd, v)
		},
	}
	return command
}
