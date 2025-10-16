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

	"github.com/permguard/permguard/pkg/transport/models/pap"
)

// GrpcPAPClientMock is a mock type for the CliDependencies type.
type GrpcPAPClientMock struct {
	mock.Mock
}

// CreateLedger creates a ledger.
func (m *GrpcPAPClientMock) CreateLedger(zoneID int64, kind string, name string) (*pap.Ledger, error) {
	args := m.Called(zoneID, kind, name)
	var r0 *pap.Ledger
	if val, ok := args.Get(0).(*pap.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateLedger updates a ledger.
func (m *GrpcPAPClientMock) UpdateLedger(ledger *pap.Ledger) (*pap.Ledger, error) {
	args := m.Called(ledger)
	var r0 *pap.Ledger
	if val, ok := args.Get(0).(*pap.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteLedger deletes a ledger.
func (m *GrpcPAPClientMock) DeleteLedger(zoneID int64, ledgerID string) (*pap.Ledger, error) {
	args := m.Called(zoneID, ledgerID)
	var r0 *pap.Ledger
	if val, ok := args.Get(0).(*pap.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchLedgers returns all ledgers.
func (m *GrpcPAPClientMock) FetchLedgers(page int32, pageSize int32, zoneID int64) ([]pap.Ledger, error) {
	args := m.Called(page, pageSize, zoneID)
	var r0 []pap.Ledger
	if val, ok := args.Get(0).([]pap.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchLedgersByID returns all ledgers filtering by ledger id.
func (m *GrpcPAPClientMock) FetchLedgersByID(page int32, pageSize int32, zoneID int64, ledgerID string) ([]pap.Ledger, error) {
	args := m.Called(page, pageSize, zoneID, ledgerID)
	var r0 []pap.Ledger
	if val, ok := args.Get(0).([]pap.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchLedgersByName returns all ledgers filtering by name.
func (m *GrpcPAPClientMock) FetchLedgersByName(page int32, pageSize int32, zoneID int64, name string) ([]pap.Ledger, error) {
	args := m.Called(page, pageSize, zoneID, name)
	var r0 []pap.Ledger
	if val, ok := args.Get(0).([]pap.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchLedgersBy returns all ledgers filtering by ledger id and name.
func (m *GrpcPAPClientMock) FetchLedgersBy(page int32, pageSize int32, zoneID int64, ledgerID string, kind string, name string) ([]pap.Ledger, error) {
	args := m.Called(page, pageSize, zoneID, ledgerID, kind, name)
	var r0 []pap.Ledger
	if val, ok := args.Get(0).([]pap.Ledger); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// NewGrpcPAPClientMock creates a new GrpcPAPClientMock.
func NewGrpcPAPClientMock() *GrpcPAPClientMock {
	return &GrpcPAPClientMock{}
}
