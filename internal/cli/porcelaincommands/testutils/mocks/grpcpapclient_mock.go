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

// GrpcPAPClientMock is a mock type for the CliDependencies type.
type GrpcPAPClientMock struct {
	mock.Mock
}

// CreateRepository creates a repository.
func (m *GrpcPAPClientMock) CreateRepository(applicationID int64, name string) (*azmodels.Repository, error) {
	args := m.Called(applicationID, name)
	var r0 *azmodels.Repository
	if val, ok := args.Get(0).(*azmodels.Repository); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// UpdateRepository updates a repository.
func (m *GrpcPAPClientMock) UpdateRepository(repository *azmodels.Repository) (*azmodels.Repository, error) {
	args := m.Called(repository)
	var r0 *azmodels.Repository
	if val, ok := args.Get(0).(*azmodels.Repository); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// DeleteRepository deletes a repository.
func (m *GrpcPAPClientMock) DeleteRepository(applicationID int64, repositoryID string) (*azmodels.Repository, error) {
	args := m.Called(applicationID, repositoryID)
	var r0 *azmodels.Repository
	if val, ok := args.Get(0).(*azmodels.Repository); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchRepositories returns all repositories.
func (m *GrpcPAPClientMock) FetchRepositories(page int32, pageSize int32, applicationID int64) ([]azmodels.Repository, error) {
	args := m.Called(page, pageSize, applicationID)
	var r0 []azmodels.Repository
	if val, ok := args.Get(0).([]azmodels.Repository); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchRepositoriesByID returns all repositories filtering by repository id.
func (m *GrpcPAPClientMock) FetchRepositoriesByID(page int32, pageSize int32, applicationID int64, repositoryID string) ([]azmodels.Repository, error) {
	args := m.Called(page, pageSize, applicationID, repositoryID)
	var r0 []azmodels.Repository
	if val, ok := args.Get(0).([]azmodels.Repository); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchRepositoriesByName returns all repositories filtering by name.
func (m *GrpcPAPClientMock) FetchRepositoriesByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodels.Repository, error) {
	args := m.Called(page, pageSize, applicationID, name)
	var r0 []azmodels.Repository
	if val, ok := args.Get(0).([]azmodels.Repository); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// FetchRepositoriesBy returns all repositories filtering by repository id and name.
func (m *GrpcPAPClientMock) FetchRepositoriesBy(page int32, pageSize int32, applicationID int64, repositoryID string, name string) ([]azmodels.Repository, error) {
	args := m.Called(page, pageSize, applicationID, repositoryID, name)
	var r0 []azmodels.Repository
	if val, ok := args.Get(0).([]azmodels.Repository); ok {
		r0 = val
	}
	return r0, args.Error(1)
}

// NewGrpcPAPClientMock creates a new GrpcPAPClientMock.
func NewGrpcPAPClientMock() *GrpcPAPClientMock {
	return &GrpcPAPClientMock{}
}
