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

// Package mocks implements mocks for testing.
package mocks

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	mock "github.com/stretchr/testify/mock"

	azcli "github.com/permguard/permguard/pkg/cli"
)

// CliDependenciesMock is a mock type for the CliDependencies type.
type CliDependenciesMock struct {
	mock.Mock
}

// CreateContext creates a new context.
func (m *CliDependenciesMock) CreateContext(cmd *cobra.Command, v *viper.Viper) (azcli.CliContext, error) {
	args := m.Called(cmd, v)
	var r0 azcli.CliContext
	if val, ok := args.Get(0).(azcli.CliContext); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreatePrinter creates a new printer.
func (m *CliDependenciesMock) CreatePrinter(ctx azcli.CliContext, cmd *cobra.Command, v *viper.Viper) (*azcli.CliPrinter, error) {
	args := m.Called(ctx, cmd, v)
	var r0 *azcli.CliPrinter
	if val, ok := args.Get(0).(*azcli.CliPrinter); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateContextAndPrinter creates a new context and printer.
func (m *CliDependenciesMock)  CreateContextAndPrinter(cmd *cobra.Command, v *viper.Viper) (azcli.CliContext, *azcli.CliPrinter, error) {
	args := m.Called(cmd, v)
	var r0 azcli.CliContext
	if val1, ok := args.Get(0).(azcli.CliContext); ok {
		r0 = val1
	}
	var r1 *azcli.CliPrinter
	if val2, ok := args.Get(0).(*azcli.CliPrinter); ok {
		r1 = val2
	}
	return r0, r1, args.Error(2)
}

// NewCliDependenciesMock creates a new CliDependenciesMock.
func NewCliDependenciesMock() *CliDependenciesMock {
	return &CliDependenciesMock{}
}
