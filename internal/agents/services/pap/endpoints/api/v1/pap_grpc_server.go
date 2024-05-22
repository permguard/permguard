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

package v1

import (
	"context"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azservices "github.com/permguard/permguard/pkg/agents/services"
)

// PAPService is the service for the PAP.
type PAPService interface {
	Setup() error
	CreateRepository(repository *azmodels.Repository) (*azmodels.Repository, error)
	UpdateRepository(repository *azmodels.Repository) (*azmodels.Repository, error)
	DeleteRepository(accountID int64, repositoryID string) (*azmodels.Repository, error)
	GetAllRepositories(accountID int64, fields map[string]any) ([]azmodels.Repository, error)
	UpdateSchema(schema *azmodels.Schema) (*azmodels.Schema, error)
	GetAllSchemas(accountID int64, fields map[string]any) ([]azmodels.Schema, error)
}

// NewV1PAPServer creates a new PAP server.
func NewV1PAPServer(endpointCtx *azservices.EndpointContext, Service PAPService) (*V1PAPServer, error) {
	return &V1PAPServer{
		ctx:     endpointCtx,
		service: Service,
	}, nil
}

// V1PAPServer is the gRPC server for the PAP.
type V1PAPServer struct {
	UnimplementedV1PAPServiceServer
	ctx     *azservices.EndpointContext
	service PAPService
}

// CreateRepository creates a new repository.
func (s V1PAPServer) CreateRepository(ctx context.Context, repositoryRequest *RepositoryCreateRequest) (*RepositoryResponse, error) {
	repository, err := s.service.CreateRepository(&azmodels.Repository{AccountID: repositoryRequest.AccountID, Name: repositoryRequest.Name})
	if err != nil {
		return nil, err
	}
	return MapAgentRepositoryToGrpcRepositoryResponse(repository)
}

// UpdateRepository updates a repository.
func (s V1PAPServer) UpdateRepository(ctx context.Context, repositoryRequest *RepositoryUpdateRequest) (*RepositoryResponse, error) {
	repository, err := s.service.UpdateRepository((&azmodels.Repository{RepositoryID: repositoryRequest.RepositoryID, AccountID: repositoryRequest.AccountID, Name: repositoryRequest.Name}))
	if err != nil {
		return nil, err
	}
	return MapAgentRepositoryToGrpcRepositoryResponse(repository)
}

// DeleteRepository deletes a repository.
func (s V1PAPServer) DeleteRepository(ctx context.Context, repositoryRequest *RepositoryDeleteRequest) (*RepositoryResponse, error) {
	repository, err := s.service.DeleteRepository(repositoryRequest.AccountID, repositoryRequest.RepositoryID)
	if err != nil {
		return nil, err
	}
	return MapAgentRepositoryToGrpcRepositoryResponse(repository)
}

// GetAllRepositories returns all the repositories.
func (s V1PAPServer) GetAllRepositories(ctx context.Context, repositoryRequest *RepositoryGetRequest) (*RepositoryListResponse, error) {
	fields := map[string]any{}
	fields[azmodels.FieldRepositoryAccountID] = repositoryRequest.AccountID
	if repositoryRequest.Name != nil {
		fields[azmodels.FieldRepositoryName] = *repositoryRequest.Name
	}
	if repositoryRequest.RepositoryID != nil {
		fields[azmodels.FieldRepositoryRepositoryID] = *repositoryRequest.RepositoryID
	}
	repositories, err := s.service.GetAllRepositories(repositoryRequest.AccountID, fields)
	if err != nil {
		return nil, err
	}
	repositoryList := &RepositoryListResponse{
		Repositories: make([]*RepositoryResponse, len(repositories)),
	}
	for i, repository := range repositories {
		cvtedRepository, err := MapAgentRepositoryToGrpcRepositoryResponse(&repository)
		if err != nil {
			return nil, err
		}
		repositoryList.Repositories[i] = cvtedRepository
	}
	return repositoryList, nil
}

// UpdateSchema updates a schema.
func (s V1PAPServer) UpdateSchema(ctx context.Context, schemaRequest *SchemaUpdateRequest) (*SchemaResponse, error) {
	schemaID := ""
	if schemaRequest.SchemaID != nil {
		schemaID = *schemaRequest.SchemaID
	}
	accountID := schemaRequest.AccountID
	repositoryID := ""
	if schemaRequest.RepositoryID != nil {
		repositoryID = *schemaRequest.RepositoryID
	}
	domains, err := MapGrpcSchemaDomainResponseToAgentSchemaDomains(schemaRequest.Domains)
	if err != nil {
		return nil, err
	}
	schema := &azmodels.Schema{
		SchemaID:      schemaID,
		AccountID:     accountID,
		RepositoryID:  repositoryID,
		SchemaDomains: domains,
	}
	schema, err = s.service.UpdateSchema(schema)
	if err != nil {
		return nil, err
	}
	return MapAgentSchemaToGrpcSchemaResponse(schema)
}

// GetAllSchemas gets all schemas.
func (s V1PAPServer) GetAllSchemas(ctx context.Context, schemaRequest *SchemaGetRequest) (*SchemaListResponse, error) {
	fields := map[string]any{}
	fields[azmodels.FieldSchemaAccountID] = schemaRequest.AccountID
	if schemaRequest.SchemaID != nil {
		fields[azmodels.FieldSchemaAccountID] = *schemaRequest.SchemaID
	}
	schemas, err := s.service.GetAllSchemas(schemaRequest.AccountID, fields)
	if err != nil {
		return nil, err
	}
	schemaList := &SchemaListResponse{
		Schemas: make([]*SchemaResponse, len(schemas)),
	}
	for i, schema := range schemas {
		cvtedSchema, err := MapAgentSchemaToGrpcSchemaResponse(&schema)
		if err != nil {
			return nil, err
		}
		schemaList.Schemas[i] = cvtedSchema
	}
	return schemaList, nil
}
