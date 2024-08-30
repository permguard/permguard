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
	mock "github.com/stretchr/testify/mock"

	azclients "github.com/permguard/permguard/pkg/agents/clients"
	azcli "github.com/permguard/permguard/pkg/cli"
)

// CliDependenciesMock is a mock type for the CliDependencies type.
type CliDependenciesMock struct {
	mock.Mock
}

// CreatePrinter creates a new printer.
func (m *CliDependenciesMock) CreatePrinter(verbose bool, output string) (azcli.CliPrinter, error) {
	args := m.Called(verbose, output)
	var r0 azcli.CliPrinter
	if val, ok := args.Get(0).(azcli.CliPrinter); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateGrpcAAPClient creates a new gRPC AAP client.
func (m *CliDependenciesMock) CreateGrpcAAPClient(aapTarget string) (azclients.GrpcAAPClient, error) {
	args := m.Called(aapTarget)
	var r0 azclients.GrpcAAPClient
	if val, ok := args.Get(0).(azclients.GrpcAAPClient); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateGrpcPAPClient creates a new gRPC PAP client.
func (m *CliDependenciesMock) CreateGrpcPAPClient(papTarget string) (azclients.GrpcPAPClient, error) {
	args := m.Called(papTarget)
	var r0 azclients.GrpcPAPClient
	if val, ok := args.Get(0).(azclients.GrpcPAPClient); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// NewCliDependenciesMock creates a new CliDependenciesMock.
func NewCliDependenciesMock() *CliDependenciesMock {
	return &CliDependenciesMock{}
}
