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
)

// PrinterMock is a mock type for the CliDependencies type.
type PrinterMock struct {
	mock.Mock
}

// Print prints the message.
func (m *PrinterMock) Print(message string) {
	m.Called(message)
}

// PrintMap prints the output.
func (m *PrinterMock) PrintMap(output map[string]any) {
	m.Called(output)
}

// Println prints the message.
func (m *PrinterMock) Println(message string) {
	m.Called(message)
}

// PrintlnMap prints the output.
func (m *PrinterMock) PrintlnMap(output map[string]any) {
	m.Called(output)
}

// Error prints the error.
func (m *PrinterMock) Error(err error) {
	m.Called(err)
}

// ErrorWithOutput prints the error with the output.
func (m *PrinterMock) ErrorWithOutput(output map[string]any, err error) {
	m.Called(output, err)
}

// NewPrinterMock creates a new PrinterMock.
func NewPrinterMock() *PrinterMock {
	return &PrinterMock{}
}
