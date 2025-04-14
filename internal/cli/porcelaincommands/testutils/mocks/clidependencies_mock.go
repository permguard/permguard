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

	azlang "github.com/permguard/permguard/pkg/authz/languages"
	azcli "github.com/permguard/permguard/pkg/cli"
	azclients "github.com/permguard/permguard/pkg/transport/clients"
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

// CreateGrpcZAPClient creates a new gRPC ZAP client.
func (m *CliDependenciesMock) CreateGrpcZAPClient(zapTarget string) (azclients.GrpcZAPClient, error) {
	args := m.Called(zapTarget)
	var r0 azclients.GrpcZAPClient
	if val, ok := args.Get(0).(azclients.GrpcZAPClient); ok {
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

// CreateGrpcPDPClient creates a new gRPC PDP client.
func (m *CliDependenciesMock) CreateGrpcPDPClient(pdpTarget string) (azclients.GrpcPDPClient, error) {
	args := m.Called(pdpTarget)
	var r0 azclients.GrpcPDPClient
	if val, ok := args.Get(0).(azclients.GrpcPDPClient); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// GetLanguageFactory returns the language factory.
func (m *CliDependenciesMock) GetLanguageFactory() (azlang.LanguageFactory, error) {
	args := m.Called()
	var r0 azlang.LanguageFactory
	if val, ok := args.Get(0).(azlang.LanguageFactory); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// NewCliDependenciesMock creates a new CliDependenciesMock.
func NewCliDependenciesMock() *CliDependenciesMock {
	return &CliDependenciesMock{}
}
