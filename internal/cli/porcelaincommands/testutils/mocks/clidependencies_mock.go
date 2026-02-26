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

package mocks

import (
	mock "github.com/stretchr/testify/mock"

	"github.com/permguard/permguard/pkg/authz/languages"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/transport/clients"
)

// CliDependenciesMock is a mock type for the CliDependencies type.
type CliDependenciesMock struct {
	mock.Mock
}

// CreatePrinter creates a new printer.
func (m *CliDependenciesMock) CreatePrinter(verbose bool, output string) (cli.Printer, error) {
	args := m.Called(verbose, output)
	var r0 cli.Printer
	if val, ok := args.Get(0).(cli.Printer); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateGrpcZAPClient creates a new gRPC ZAP client.
func (m *CliDependenciesMock) CreateGrpcZAPClient(zapTarget string) (clients.GrpcZAPClient, error) {
	args := m.Called(zapTarget)
	var r0 clients.GrpcZAPClient
	if val, ok := args.Get(0).(clients.GrpcZAPClient); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateGrpcPAPClient creates a new gRPC PAP client.
func (m *CliDependenciesMock) CreateGrpcPAPClient(papTarget string) (clients.GrpcPAPClient, error) {
	args := m.Called(papTarget)
	var r0 clients.GrpcPAPClient
	if val, ok := args.Get(0).(clients.GrpcPAPClient); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// CreateGrpcPDPClient creates a new gRPC PDP client.
func (m *CliDependenciesMock) CreateGrpcPDPClient(pdpTarget string) (clients.GrpcPDPClient, error) {
	args := m.Called(pdpTarget)
	var r0 clients.GrpcPDPClient
	if val, ok := args.Get(0).(clients.GrpcPDPClient); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// LanguageFactory returns the language factory.
func (m *CliDependenciesMock) LanguageFactory() (languages.LanguageFactory, error) {
	args := m.Called()
	var r0 languages.LanguageFactory
	if val, ok := args.Get(0).(languages.LanguageFactory); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// NewCliDependenciesMock creates a new CliDependenciesMock.
func NewCliDependenciesMock() *CliDependenciesMock {
	return &CliDependenciesMock{}
}
