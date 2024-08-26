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

	azconfigs "github.com/permguard/permguard/pkg/configs"
	azcli "github.com/permguard/permguard/pkg/cli"
)

// CliCommandContext is the context for the Cli.
type CliCommandContext struct {
	v       *viper.Viper
	verbose bool
	output  string
}

// newCliContext creates a new CliContext.
func newCliContext(cmd *cobra.Command, v *viper.Viper) (*CliCommandContext, error) {
	ctx := &CliCommandContext{
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
func (c *CliCommandContext) GetViper() *viper.Viper {
	return c.v
}

// GetVerbose returns true if the verbose.
func (c *CliCommandContext) GetVerbose() bool {
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

// GetAAPTarget returns the aap target.
func (c *CliCommandContext) GetAAPTarget() string {
	target := c.v.Get(azconfigs.FlagName(flagPrefixAAP, flagSuffixAAPTarget))
	return target.(string)
}

// GetPAPTarget returns the pap target.
func (c *CliCommandContext) GetPAPTarget() string {
	target := c.v.Get(azconfigs.FlagName(flagPrefixPAP, flagSuffixPAPTarget))
	return target.(string)
}
