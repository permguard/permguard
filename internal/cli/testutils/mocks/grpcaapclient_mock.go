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

	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// GrpcAAPClientMock is a mock type for the CliDependencies type.
type GrpcAAPClientMock struct {
	mock.Mock
}

// CreateAccount creates a new account.
func (m *GrpcAAPClientMock) CreateAccount(name string) (*azmodels.Account, error){
	args := m.Called(name)
	var r0 *azmodels.Account
	if val, ok := args.Get(0).(*azmodels.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateAccount updates an account.
func (m *GrpcAAPClientMock) UpdateAccount(account *azmodels.Account) (*azmodels.Account, error){
	args := m.Called(account)
	var r0 *azmodels.Account
	if val, ok := args.Get(0).(*azmodels.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}
// DeleteAccount deletes an account.
func (m *GrpcAAPClientMock) DeleteAccount(accountID int64) (*azmodels.Account, error){
	args := m.Called(accountID)
	var r0 *azmodels.Account
	if val, ok := args.Get(0).(*azmodels.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}
// FetchAccounts fetches accounts.
func (m *GrpcAAPClientMock) FetchAccounts(page int32, pageSize int32) ([]azmodels.Account, error){
	args := m.Called(page)
	var r0 []azmodels.Account
	if val, ok := args.Get(0).([]azmodels.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchAccountsByID fetches accounts by ID.
func (m *GrpcAAPClientMock) FetchAccountsByID(page int32, pageSize int32, accountID int64) ([]azmodels.Account, error){
	args := m.Called(page, pageSize, accountID)
	var r0 []azmodels.Account
	if val, ok := args.Get(0).([]azmodels.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchAccountsByName fetches accounts by name.
func (m *GrpcAAPClientMock) FetchAccountsByName(page int32, pageSize int32, name string) ([]azmodels.Account, error) {
	args := m.Called(page, pageSize, name)
	var r0 []azmodels.Account
	if val, ok := args.Get(0).([]azmodels.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchAccountsBy fetches accounts by.
func (m *GrpcAAPClientMock) FetchAccountsBy(page int32, pageSize int32, accountID int64, name string) ([]azmodels.Account, error) {
	args := m.Called(page, pageSize, accountID, name)
	var r0 []azmodels.Account
	if val, ok := args.Get(0).([]azmodels.Account); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// NewGrpcAAPClientMock creates a new GrpcAAPClientMock.
func NewGrpcAAPClientMock() *GrpcAAPClientMock {
	return &GrpcAAPClientMock{}
}
