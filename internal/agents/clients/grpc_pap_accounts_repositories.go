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
	"context"
	"errors"

	azapiv1pap "github.com/permguard/permguard/internal/agents/services/pap/endpoints/api/v1"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// CreateRepository creates a new repository.
func (c *GrpcPAPClient) CreateRepository(accountID int64, name string) (*azmodels.Repository, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	repository, err := client.CreateRepository(context.Background(), &azapiv1pap.RepositoryCreateRequest{AccountID: accountID, Name: name})
	if err != nil {
		return nil, err
	}
	return azapiv1pap.MapGrpcRepositoryResponseToAgentRepository(repository)
}

// UpdateRepository updates an repository.
func (c *GrpcPAPClient) UpdateRepository(repository *azmodels.Repository) (*azmodels.Repository, error) {
	if repository == nil {
		return nil, errors.New("client: invalid repository instance")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedRepository, err := client.UpdateRepository(context.Background(), &azapiv1pap.RepositoryUpdateRequest{
		RepositoryID: repository.RepositoryID,
		AccountID:    repository.AccountID,
		Name:         repository.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1pap.MapGrpcRepositoryResponseToAgentRepository(updatedRepository)
}

// DeleteRepository deletes an repository.
func (c *GrpcPAPClient) DeleteRepository(accountID int64, repositoryID string) (*azmodels.Repository, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	repository, err := client.DeleteRepository(context.Background(), &azapiv1pap.RepositoryDeleteRequest{AccountID: accountID, RepositoryID: repositoryID})
	if err != nil {
		return nil, err
	}
	return azapiv1pap.MapGrpcRepositoryResponseToAgentRepository(repository)
}

// FetchRepositories returns all repositories.
func (c *GrpcPAPClient) FetchRepositories(page int32, pageSize int32, accountID int64) ([]azmodels.Repository, error) {
	return c.FetchRepositoriesBy(page, pageSize, accountID, "", "")
}

// FetchRepositoriesByID returns all repositories filtering by repository id.
func (c *GrpcPAPClient) FetchRepositoriesByID(page int32, pageSize int32, accountID int64, repositoryID string) ([]azmodels.Repository, error) {
	return c.FetchRepositoriesBy(page, pageSize, accountID, repositoryID, "")
}

// FetchRepositoriesByName returns all repositories filtering by name.
func (c *GrpcPAPClient) FetchRepositoriesByName(page int32, pageSize int32, accountID int64, name string) ([]azmodels.Repository, error) {
	return c.FetchRepositoriesBy(page, pageSize, accountID, "", name)
}

// FetchRepositoriesBy returns all repositories filtering by repository id and name.
func (c *GrpcPAPClient) FetchRepositoriesBy(page int32, pageSize int32, accountID int64, repositoryID string, name string) ([]azmodels.Repository, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	repositoryFetchRequest := &azapiv1pap.RepositoryFetchRequest{}
	repositoryFetchRequest.Page = &page
	repositoryFetchRequest.PageSize = &pageSize
	if accountID > 0 {
		repositoryFetchRequest.AccountID = accountID
	}
	if name != "" {
		repositoryFetchRequest.Name = &name
	}
	if repositoryID != "" {
		repositoryFetchRequest.RepositoryID = &repositoryID
	}
	repositoryList, err := client.FetchRepositories(context.Background(), repositoryFetchRequest)
	if err != nil {
		return nil, err
	}
	repositories := make([]azmodels.Repository, len(repositoryList.Repositories))
	for i, repository := range repositoryList.Repositories {
		repository, err := azapiv1pap.MapGrpcRepositoryResponseToAgentRepository(repository)
		if err != nil {
			return nil, err
		}
		repositories[i] = *repository
	}
	return repositories, nil
}
