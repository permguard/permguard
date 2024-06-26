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

package cli

import (
	"errors"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azcli "github.com/permguard/permguard/pkg/cli"
	azconfigs "github.com/permguard/permguard/pkg/configs"
)

// createContextAndPrinter creates a new cli context and printer.
func createContextAndPrinter(cmd *cobra.Command, v *viper.Viper) (*CliContext, *azcli.CliPrinter, error) {
	ctx, err := newCliContext(cmd, v)
	if err != nil {
		return nil, nil, err
	}
	printer, err := azcli.NewCliPrinter(ctx.GetVerbose(), ctx.GetOutput())
	if err != nil {
		return nil, nil, err
	}
	return ctx, printer, nil
}

// CliContext is the context for the CLI.
type CliContext struct {
	v       *viper.Viper
	verbose bool
	output  string
}

// newCliContext creates a new CliContext.
func newCliContext(cmd *cobra.Command, v *viper.Viper) (*CliContext, error) {
	ctx := &CliContext{
		v: v,
	}
	output, err := cmd.Flags().GetString(flagOutput)
	if err != nil {
		return nil, err
	}
	ctx.output = strings.ToUpper(strings.TrimSpace(output))
	if ctx.output != azcli.OutputTerminal && ctx.output != azcli.OutputJSON {
		return nil, errors.New("cli: invalid output")
	}
	verbose, err := cmd.Flags().GetBool(flagVerbose)
	if err != nil {
		return nil, err
	}
	ctx.verbose = verbose
	return ctx, nil
}

// GetViper returns the viper.
func (c *CliContext) GetViper() *viper.Viper {
	return c.v
}

// GetVerbose returns true if the verbose.
func (c *CliContext) GetVerbose() bool {
	return c.verbose
}

// GetOutput returns the output.
func (c *CliContext) GetOutput() string {
	return c.output
}

// IsTerminalOutput returns true if the output is json.
func (c *CliContext) IsTerminalOutput() bool {
	return c.GetOutput() == azcli.OutputTerminal
}

// IsJSONOutput returns true if the output is json.
func (c *CliContext) IsJSONOutput() bool {
	return c.GetOutput() == azcli.OutputJSON
}

// GetAAPTarget returns the aap target.
func (c *CliContext) GetAAPTarget() string {
	target := c.v.Get(azconfigs.FlagName(flagPrefixAAP, flagSuffixAAPTarget))
	return target.(string)
}

// GetPAPTarget returns the pap target.
func (c *CliContext) GetPAPTarget() string {
	target := c.v.Get(azconfigs.FlagName(flagPrefixPAP, flagSuffixPAPTarget))
	return target.(string)
}
