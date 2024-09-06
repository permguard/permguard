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

package common

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azvalidators "github.com/permguard/permguard-authz/pkg/extensions/validators"
	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

// CreateContextAndPrinter creates a new cli context and printer.
func CreateContextAndPrinter(deps azcli.CliDependenciesProvider, cmd *cobra.Command, v *viper.Viper) (*CliCommandContext, azcli.CliPrinter, error) {
	ctx, err := newCliContext(cmd, v)
	if err != nil {
		return nil, nil, err
	}
	printer, err := deps.CreatePrinter(ctx.IsVerbose(), ctx.GetOutput())
	if err != nil {
		return nil, nil, err
	}
	return ctx, printer, nil
}

// CliCommandContext is the context for the Cli.
type CliCommandContext struct {
	v       *viper.Viper
	workDir string
	verbose bool
	output  string
}

// newCliContext creates a new CliContext.
func newCliContext(cmd *cobra.Command, v *viper.Viper) (*CliCommandContext, error) {
	ctx := &CliCommandContext{
		v: v,
	}
	workDir, err := cmd.Flags().GetString(FlagWorkingDirectory)
	if err != nil {
		return nil, err
	}
	if !azvalidators.IsValidPath(workDir) {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliDirectoryOperation, fmt.Sprintf("cli: %s is an invalid work directory", workDir))
	}
	ctx.workDir = workDir
	output, err := cmd.Flags().GetString(FlagOutput)
	if err != nil {
		return nil, err
	}
	ctx.output = strings.ToUpper(strings.TrimSpace(output))
	if ctx.output != azcli.OutputTerminal && ctx.output != azcli.OutputJSON {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliDirectoryOperation, fmt.Sprintf("cli: %s is an invalid output", output))
	}
	verbose, err := cmd.Flags().GetBool(FlagVerbose)
	if err != nil {
		return nil, err
	}
	ctx.verbose = verbose
	return ctx, nil
}

// GetClientVersion returns the client version.
func (c *CliCommandContext) GetClientVersion() string {
	return "0.0.1"
}

// GetViper returns the viper.
func (c *CliCommandContext) GetViper() *viper.Viper {
	return c.v
}

// IsVerbose returns true if verbosity is enabled.
func (c *CliCommandContext) IsVerbose() bool {
	return c.verbose
}

// GetOutput returns the output.
func (c *CliCommandContext) GetOutput() string {
	return c.output
}

// IsTerminalOutput returns true if the output is json.
func (c *CliCommandContext) IsTerminalOutput() bool {
	return c.GetOutput() == azcli.OutputTerminal
}

// IsJSONOutput returns true if the output is json.
func (c *CliCommandContext) IsJSONOutput() bool {
	return c.GetOutput() == azcli.OutputJSON
}

// GetWorkDir returns the work directory.
func (c *CliCommandContext) GetWorkDir() string {
	return c.workDir
}

// GetAAPTarget returns the aap target.
func (c *CliCommandContext) GetAAPTarget() string {
	target := c.v.Get(azconfigs.FlagName(FlagPrefixAAP, FlagSuffixAAPTarget))
	return target.(string)
}

// GetPAPTarget returns the pap target.
func (c *CliCommandContext) GetPAPTarget() string {
	target := c.v.Get(azconfigs.FlagName(FlagPrefixPAP, FlagSuffixPAPTarget))
	return target.(string)
}
