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

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/workspace"
	azwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
)

const (
	// commandNameForWorkspacesRemoteAdd is the command name for workspaces remoteadd.
	commandNameForWorkspacesRemoteAdd = "workspaces-remote.add"

	// flagZAP is the flag name for the ZAP port.
	flagZAP = "zap"
	// flagPAP is the flag name for the PAP port.
	flagPAP = "pap"
	// flagScheme is the flag name for the gRPC scheme.
	flagScheme = "scheme"
)

// runECommandForRemoteAddWorkspace runs the command for adding a workspace remote.
func runECommandForRemoteAddWorkspace(args []string, deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) error {
	ctx, printer, err := common.CreateContextAndPrinter(deps, cmd, v)
	if err != nil {
		color.Red(fmt.Sprintf("%s", err))
		return common.ErrCommandSilent
	}
	langAbs, err := deps.LanguageFactory()
	if err != nil {
		return failWithDetails(ctx, printer, err)
	}
	wksMgr, err := workspace.NewInternalManager(ctx, langAbs)
	if err != nil {
		return failWithDetails(ctx, printer, err)
	}
	wksMgr.ExecPrintContext(nil, outFunc(ctx, printer))
	if len(args) < 2 {
		return failWithDetails(ctx, printer, errors.New("cli: failed to add the remote\ntwo arguments are required: <remote-name> <server-address>"))
	}
	remote := args[0]
	rawServer := args[1]
	serverScheme, server := azwkscommon.ParseServerScheme(rawServer)
	zapPort := v.GetInt(options.FlagName(commandNameForWorkspacesRemoteAdd, flagZAP))
	papPort := v.GetInt(options.FlagName(commandNameForWorkspacesRemoteAdd, flagPAP))
	flagScheme := v.GetString(options.FlagName(commandNameForWorkspacesRemoteAdd, flagScheme))
	scheme := azwkscommon.ResolveScheme(serverScheme, flagScheme)
	output, err := wksMgr.ExecAddRemote(remote, server, zapPort, papPort, scheme, outFunc(ctx, printer))
	if err != nil {
		printer.ErrorWithOutput(finalizeErrorOutput(ctx, output), errors.Join(errors.New("cli: failed to add the remote"), err))
		return common.ErrCommandSilent
	}
	if ctx.IsJSONOutput() {
		printer.PrintlnMap(finalizeOutput(ctx, output))
	}
	return nil
}

// CreateCommandForWorkspaceRemoteAdd creates a command for adding a workspace remote.
func CreateCommandForWorkspaceRemoteAdd(deps cli.DependenciesProvider, v *viper.Viper) *cobra.Command {
	command := &cobra.Command{
		Use:   "add",
		Short: `add a new remote ledger to track and interact with`,
		Long: common.BuildCliLongTemplate(`This command adds a new remote ledger to track and interact with.

Examples:
  # add a new remote ledger to track and interact with
  permguard remote add origin localhost`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runECommandForRemoteAddWorkspace(args, deps, cmd, v)
		},
	}

	command.Flags().Int(flagZAP, 9091, "specify the port number for the ZAP")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspacesRemoteAdd, flagZAP), command.Flags().Lookup(flagZAP))
	command.Flags().Int(flagPAP, 9092, "specify the port number for the PAP")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspacesRemoteAdd, flagPAP), command.Flags().Lookup(flagPAP))
	command.Flags().String(flagScheme, "", "specify the gRPC scheme: 'grpc' (plaintext) or 'grpcs' (TLS), overrides scheme prefix in server")
	_ = v.BindPFlag(options.FlagName(commandNameForWorkspacesRemoteAdd, flagScheme), command.Flags().Lookup(flagScheme))
	return command
}
