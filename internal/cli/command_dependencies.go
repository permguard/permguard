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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azcli "github.com/permguard/permguard/pkg/cli"
)

// cliDependencies implements the Cli dependencies.
type cliDependencies struct {
}

// CreateContext creates a new context.
func (c *cliDependencies) CreateContext(cmd *cobra.Command, v *viper.Viper) (azcli.CliContext, error) {
	ctx, err := newCliContext(cmd, v)
	if err != nil {
		return nil, err
	}
	return ctx, nil
}

// CreatePrinter creates a new printer.
func (c *cliDependencies) CreatePrinter(ctx azcli.CliContext, cmd *cobra.Command, v *viper.Viper) (*azcli.CliPrinter, error) {
	printer, err := azcli.NewCliPrinter(ctx.GetVerbose(), ctx.GetOutput())
	if err != nil {
		return nil, err
	}
	return printer, nil
}

// CreateContextAndPrinter creates a new context and printer.
func (c *cliDependencies) CreateContextAndPrinter(cmd *cobra.Command, v *viper.Viper) (azcli.CliContext, *azcli.CliPrinter, error) {
	ctx, err := c.CreateContext(cmd, v)
	if err != nil {
		return nil, nil, err
	}
	printer, err := c.CreatePrinter(ctx, cmd, v)
	if err != nil {
		return nil, nil, err
	}
	return ctx, printer, nil
}

// NewCliDependenciesProvider creates a new CliDependenciesProvider.
func NewCliDependenciesProvider() (azcli.CliDependenciesProvider, error) {
	return &cliDependencies{}, nil
}
