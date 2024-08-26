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

package clients

import (
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// GrpcPAPClient is the gRPC PAP client servicer.
type GrpcPAPClient interface {
	// CreateRepository creates a repository.
	CreateRepository(accountID int64, name string) (*azmodels.Repository, error)
	// UpdateRepository updates a repository.
	UpdateRepository(repository *azmodels.Repository) (*azmodels.Repository, error)
	// DeleteRepository deletes a repository.
	DeleteRepository(accountID int64, repositoryID string) (*azmodels.Repository, error)
	// FetchRepositories returns all repositories.
	FetchRepositories(page int32, pageSize int32, accountID int64) ([]azmodels.Repository, error)
	// FetchRepositoriesByID returns all repositories filtering by repository id.
	FetchRepositoriesByID(page int32, pageSize int32, accountID int64, repositoryID string) ([]azmodels.Repository, error)
	// FetchRepositoriesByName returns all repositories filtering by name.
	FetchRepositoriesByName(page int32, pageSize int32, accountID int64, name string) ([]azmodels.Repository, error)
	// FetchRepositoriesBy returns all repositories filtering by repository id and name.
	FetchRepositoriesBy(page int32, pageSize int32, accountID int64, repositoryID string, name string) ([]azmodels.Repository, error)
}
