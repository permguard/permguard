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
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/common/pkg/extensions/validators"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
)

// Build information variables.
var (
	Version   string
	BuildTime string
	GitCommit string
)

// CreateContextAndPrinter creates a new cli context and printer.
func CreateContextAndPrinter(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) (*CliCommandContext, cli.Printer, error) {
	ctx, err := newCliContext(cmd, v)
	if err != nil {
		return nil, nil, err
	}
	printer, err := deps.CreatePrinter(ctx.IsVerbose(), ctx.Output())
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
	if !validators.IsValidPath(workDir) {
		return nil, fmt.Errorf("cli: %s is an invalid work directory", workDir)
	}
	ctx.workDir = workDir
	output, err := cmd.Flags().GetString(FlagOutput)
	if err != nil {
		return nil, err
	}
	ctx.output = strings.ToUpper(strings.TrimSpace(output))
	if ctx.output != cli.OutputTerminal && ctx.output != cli.OutputJSON {
		return nil, fmt.Errorf("cli: %s is an invalid output", output)
	}
	verbose, err := cmd.Flags().GetBool(FlagVerbose)
	if err != nil {
		return nil, err
	}
	ctx.verbose = verbose
	return ctx, nil
}

// ClientVersion returns the client version.
func (c *CliCommandContext) ClientVersion() (string, map[string]any) {
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

// Viper returns the viper.
func (c *CliCommandContext) Viper() *viper.Viper {
	return c.v
}

// IsVerbose returns true if verbosity is enabled.
func (c *CliCommandContext) IsVerbose() bool {
	return c.verbose
}

// Output returns the output.
func (c *CliCommandContext) Output() string {
	return c.output
}

// IsTerminalOutput returns true if the output is json.
func (c *CliCommandContext) IsTerminalOutput() bool {
	return c.Output() == cli.OutputTerminal
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
	return c.Output() == cli.OutputJSON
}

// IsVerboseJSONOutput returns true if the output is json and verbosity is enabled.
func (c *CliCommandContext) IsVerboseJSONOutput() bool {
	return c.IsJSONOutput() && c.IsVerbose()
}

// WorkDir returns the work directory.
func (c *CliCommandContext) WorkDir() string {
	return c.workDir
}

// ZAPEndpoint returns the zap endpoint.
func (c *CliCommandContext) ZAPEndpoint() (string, error) {
	endpoint := c.v.Get(options.FlagName(FlagPrefixZAP, FlagSuffixZAPEndpoint))
	if endpoint == nil {
		return "", errors.New("cli: zap endpoint is not set")
	}
	return endpoint.(string), nil
}

// PAPEndpoint returns the pap endpoint.
func (c *CliCommandContext) PAPEndpoint() (string, error) {
	endpoint := c.v.Get(options.FlagName(FlagPrefixPAP, FlagSuffixPAPEndpoint))
	if endpoint == nil {
		return "", errors.New("cli: pap endpoint is not set")
	}
	return endpoint.(string), nil
}

// PDPEndpoint returns the pdp endpoint.
func (c *CliCommandContext) PDPEndpoint() (string, error) {
	endpoint := c.v.Get(options.FlagName(FlagPrefixPDP, FlagSuffixPDPEndpoint))
	if endpoint == nil {
		return "", errors.New("cli: pdp endpoint is not set")
	}
	return endpoint.(string), nil
}
