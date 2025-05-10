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

	azvalidators "github.com/permguard/permguard/common/pkg/extensions/validators"
	azcli "github.com/permguard/permguard/pkg/cli"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

var (
	Version   string
	BuildTime string
	GitCommit string
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
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliDirectoryOperation, fmt.Sprintf("%s is an invalid work directory", workDir))
	}
	ctx.workDir = workDir
	output, err := cmd.Flags().GetString(FlagOutput)
	if err != nil {
		return nil, err
	}
	ctx.output = strings.ToUpper(strings.TrimSpace(output))
	if ctx.output != azcli.OutputTerminal && ctx.output != azcli.OutputJSON {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliDirectoryOperation, fmt.Sprintf("%s is an invalid output", output))
	}
	verbose, err := cmd.Flags().GetBool(FlagVerbose)
	if err != nil {
		return nil, err
	}
	ctx.verbose = verbose
	return ctx, nil
}

// GetClientVersion returns the client version.
func (c *CliCommandContext) GetClientVersion() (string, map[string]any) {
	if Version == "" {
		Version = "none"
	}
	if BuildTime == "" {
		BuildTime = "unknown"
	}
	if GitCommit == "" {
		GitCommit = "unknown"
	}
	versionMap := map[string]any{
		"version":    Version,
		"build_time": BuildTime,
		"git_commit": GitCommit,
	}
	return Version, versionMap
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

// IsNotVerboseTerminalOutput return true if the output is terminal and verbosity is not enabled.
func (c *CliCommandContext) IsNotVerboseTerminalOutput() bool {
	return c.IsTerminalOutput() && !c.IsVerbose()
}

// IsVerboseTerminalOutput returns true if the output is terminal and verbosity is enabled.
func (c *CliCommandContext) IsVerboseTerminalOutput() bool {
	return c.IsTerminalOutput() && c.IsVerbose()
}

// IsJSONOutput returns true if the output is json.
func (c *CliCommandContext) IsJSONOutput() bool {
	return c.GetOutput() == azcli.OutputJSON
}

// IsVerboseJSONOutput returns true if the output is json and verbosity is enabled.
func (c *CliCommandContext) IsVerboseJSONOutput() bool {
	return c.IsJSONOutput() && c.IsVerbose()
}

// GetWorkDir returns the work directory.
func (c *CliCommandContext) GetWorkDir() string {
	return c.workDir
}

// GetZAPTarget returns the zap target.
func (c *CliCommandContext) GetZAPTarget() (string, error) {
	target := c.v.Get(azoptions.FlagName(FlagPrefixZAP, FlagSuffixZAPTarget))
	if target == nil {
		return "", azerrors.WrapHandledSysError(azerrors.ErrCliConfiguration, fmt.Errorf("zap target is not set"))
	}
	return target.(string), nil
}

// GetPAPTarget returns the pap target.
func (c *CliCommandContext) GetPAPTarget() (string, error) {
	target := c.v.Get(azoptions.FlagName(FlagPrefixPAP, FlagSuffixPAPTarget))
	if target == nil {
		return "", azerrors.WrapHandledSysError(azerrors.ErrCliConfiguration, fmt.Errorf("pap target is not set"))
	}
	return target.(string), nil
}

// GetPDPTarget returns the pdp target.
func (c *CliCommandContext) GetPDPTarget() (string, error) {
	target := c.v.Get(azoptions.FlagName(FlagPrefixPDP, FlagSuffixPDPTarget))
	if target == nil {
		return "", azerrors.WrapHandledSysError(azerrors.ErrCliConfiguration, fmt.Errorf("pdp target is not set"))
	}
	return target.(string), nil
}
