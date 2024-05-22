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

package controllers

import (
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azStorage "github.com/permguard/permguard/pkg/agents/storage"
)

type PAPController struct {
	ctx     *azservices.ServiceContext
	storage azStorage.PAPCentralStorage
}

// Setup initializes the service.
func (s PAPController) Setup() error {
	return nil
}

func NewPAPController(serviceContext *azservices.ServiceContext, storage azStorage.PAPCentralStorage) (*PAPController, error) {
	service := PAPController{
		ctx:     serviceContext,
		storage: storage,
	}
	return &service, nil
}

// CreateRepository creates a new repository.
func (s PAPController) CreateRepository(repository *azmodels.Repository) (*azmodels.Repository, error) {
	return s.storage.CreateRepository(repository)
}

// UpdateRepository updates an repository.
func (s PAPController) UpdateRepository(repository *azmodels.Repository) (*azmodels.Repository, error) {
	return s.storage.UpdateRepository(repository)
}

// DeleteRepository deletes an repository.
func (s PAPController) DeleteRepository(accountID int64, repositoryID string) (*azmodels.Repository, error) {
	return s.storage.DeleteRepository(accountID, repositoryID)
}

// GetAllRepositories gets all repositories.
func (s PAPController) GetAllRepositories(accountID int64, fields map[string]any) ([]azmodels.Repository, error) {
	return s.storage.GetAllRepositories(accountID, fields)
}

// UpdateSchema updates a schema.
func (s PAPController) UpdateSchema(schema *azmodels.Schema) (*azmodels.Schema, error) {
	return s.storage.UpdateSchema(schema)
}

// GetAllSchemas gets all schemas.
func (s PAPController) GetAllSchemas(accountID int64, fields map[string]any) ([]azmodels.Schema, error) {
	return s.storage.GetAllSchemas(accountID, fields)
}
