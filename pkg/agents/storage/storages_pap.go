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

package storage

import (
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// PAPCentralStorage is the interface for the AAP central storage.
type PAPCentralStorage interface {
	// CreateRepository creates a new repository.
	CreateRepository(repository *azmodels.Repository) (*azmodels.Repository, error)
	// UpdateRepository updates an repository.
	UpdateRepository(repository *azmodels.Repository) (*azmodels.Repository, error)
	// DeleteRepository deletes an repository.
	DeleteRepository(accountID int64, repositoryID string) (*azmodels.Repository, error)
	// FetchRepositories gets all repositories.
	FetchRepositories(accountID int64, fields map[string]any) ([]azmodels.Repository, error)

	// UpdateSchema updates a schema.
	UpdateSchema(schema *azmodels.Schema) (*azmodels.Schema, error)
	// GetAllSchemas gets all schemas.
	GetAllSchemas(accountID int64, fields map[string]any) ([]azmodels.Schema, error)
}
