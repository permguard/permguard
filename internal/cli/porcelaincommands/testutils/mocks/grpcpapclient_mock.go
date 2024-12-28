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

	azmodels "github.com/permguard/permguard/pkg/transport/models"
)

// GrpcPAPClientMock is a mock type for the CliDependencies type.
type GrpcPAPClientMock struct {
	mock.Mock
}

// CreateLedger creates a ledger.
func (m *GrpcPAPClientMock) CreateLedger(applicationID int64, kind string, name string) (*azmodels.Ledger, error) {
	args := m.Called(applicationID, kind, name)
	var r0 *azmodels.Ledger
	if val, ok := args.Get(0).(*azmodels.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateLedger updates a ledger.
func (m *GrpcPAPClientMock) UpdateLedger(ledger *azmodels.Ledger) (*azmodels.Ledger, error) {
	args := m.Called(ledger)
	var r0 *azmodels.Ledger
	if val, ok := args.Get(0).(*azmodels.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteLedger deletes a ledger.
func (m *GrpcPAPClientMock) DeleteLedger(applicationID int64, ledgerID string) (*azmodels.Ledger, error) {
	args := m.Called(applicationID, ledgerID)
	var r0 *azmodels.Ledger
	if val, ok := args.Get(0).(*azmodels.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchLedgers returns all ledgers.
func (m *GrpcPAPClientMock) FetchLedgers(page int32, pageSize int32, applicationID int64) ([]azmodels.Ledger, error) {
	args := m.Called(page, pageSize, applicationID)
	var r0 []azmodels.Ledger
	if val, ok := args.Get(0).([]azmodels.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchLedgersByID returns all ledgers filtering by ledger id.
func (m *GrpcPAPClientMock) FetchLedgersByID(page int32, pageSize int32, applicationID int64, ledgerID string) ([]azmodels.Ledger, error) {
	args := m.Called(page, pageSize, applicationID, ledgerID)
	var r0 []azmodels.Ledger
	if val, ok := args.Get(0).([]azmodels.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchLedgersByName returns all ledgers filtering by name.
func (m *GrpcPAPClientMock) FetchLedgersByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodels.Ledger, error) {
	args := m.Called(page, pageSize, applicationID, name)
	var r0 []azmodels.Ledger
	if val, ok := args.Get(0).([]azmodels.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchLedgersBy returns all ledgers filtering by ledger id and name.
func (m *GrpcPAPClientMock) FetchLedgersBy(page int32, pageSize int32, applicationID int64, ledgerID string, kind string, name string) ([]azmodels.Ledger, error) {
	args := m.Called(page, pageSize, applicationID, ledgerID, kind, name)
	var r0 []azmodels.Ledger
	if val, ok := args.Get(0).([]azmodels.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// NewGrpcPAPClientMock creates a new GrpcPAPClientMock.
func NewGrpcPAPClientMock() *GrpcPAPClientMock {
	return &GrpcPAPClientMock{}
}
