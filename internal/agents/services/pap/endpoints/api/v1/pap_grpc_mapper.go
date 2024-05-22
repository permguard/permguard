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
	"google.golang.org/protobuf/types/known/timestamppb"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

func MapGrpcRepositoryResponseToAgentRepository(repository *RepositoryResponse) (*azmodels.Repository, error) {
	return &azmodels.Repository{
		RepositoryID: repository.RepositoryID,
		CreatedAt:    repository.CreatedAt.AsTime(),
		UpdatedAt:    repository.UpdatedAt.AsTime(),
		AccountID:    repository.AccountID,
		Name:         repository.Name,
	}, nil
}

// MapAgentRepositoryToGrpcRepositoryResponse maps the agent repository to the gRPC repository.
func MapAgentRepositoryToGrpcRepositoryResponse(repository *azmodels.Repository) (*RepositoryResponse, error) {
	return &RepositoryResponse{
		RepositoryID: repository.RepositoryID,
		CreatedAt:    timestamppb.New(repository.CreatedAt),
		UpdatedAt:    timestamppb.New(repository.UpdatedAt),
		AccountID:    repository.AccountID,
		Name:         repository.Name,
	}, nil
}

// MapPointerStringToString maps a pointer string to a string.
func MapPointerStringToString(str *string) string {
	response := ""
	if str != nil {
		response = *str
	}
	return response
}

// MapGrpcSchemaDomainsToAgentDomains maps the gRPC schema domains to the agent domains.
func MapGrpcSchemaDomainsToAgentDomains(domains []*SchemaDomain) ([]azmodels.Domain, error) {
	schemaDomains := make([]azmodels.Domain, len(domains))
	for i, domain := range domains {
		azDomain := azmodels.Domain{
			Name:        domain.Name,
			Description: MapPointerStringToString(domain.Description),
			Resources:   make([]azmodels.Resource, len(domain.Resources)),
		}
		for j, resource := range domain.Resources {
			azResource := azmodels.Resource{
				Name:        resource.Name,
				Description: MapPointerStringToString(resource.Description),
				Actions:     make([]azmodels.Action, len(resource.Actions)),
			}
			for k, action := range resource.Actions {
				azAction := azmodels.Action{
					Name:        action.Name,
					Description: MapPointerStringToString(action.Description),
				}
				azResource.Actions[k] = azAction
			}
			azDomain.Resources[j] = azResource
		}
		schemaDomains[i] = azDomain
	}
	return schemaDomains, nil
}

// MapGrpcSchemaDomainResponseToAgentSchemaDomains maps the gRPC schema to the agent schema.
func MapGrpcSchemaDomainResponseToAgentSchemaDomains(domains []*SchemaDomain) (*azmodels.SchemaDomains, error) {
	schemaDomains, err := MapGrpcSchemaDomainsToAgentDomains(domains)
	if err != nil {
		return nil, err
	}
	return &azmodels.SchemaDomains{Domains: schemaDomains}, nil
}

// MapAgentDomainToGrpcSchemaDomains maps the agent schema to the gRPC schema domains.
func MapAgentDomainToGrpcSchemaDomains(domains []azmodels.Domain) ([]*SchemaDomain, error) {
	scDomains := make([]*SchemaDomain, len(domains))
	for i, scDomain := range domains {
		domain := scDomain
		scResources := make([]*SchemaResource, len(domain.Resources))
		for j, scResource := range domain.Resources {
			resource := scResource
			schemaActions := make([]*SchemaAction, len(resource.Actions))
			description := &resource.Description
			scResources[j] = &SchemaResource{
				Name:        resource.Name,
				Description: description,
				Actions:     schemaActions,
			}
			for k, scAction := range resource.Actions {
				action := scAction
				description := &action.Description
				schemaActions[k] = &SchemaAction{
					Name:        action.Name,
					Description: description,
				}
			}
		}
		description := &domain.Description
		scDomains[i] = &SchemaDomain{
			Name:        domain.Name,
			Description: description,
			Resources:   scResources,
		}
	}
	return scDomains, nil
}

// MapAgentSchemaToGrpcSchemaResponse maps the agent schema to the gRPC schema.
func MapAgentSchemaToGrpcSchemaResponse(schema *azmodels.Schema) (*SchemaResponse, error) {
	schemaDomains, err := MapAgentDomainToGrpcSchemaDomains(schema.SchemaDomains.Domains)
	if err != nil {
		return nil, err
	}
	return &SchemaResponse{
		SchemaID:       schema.SchemaID,
		CreatedAt:      timestamppb.New(schema.CreatedAt),
		UpdatedAt:      timestamppb.New(schema.UpdatedAt),
		AccountID:      schema.AccountID,
		RepositoryID:   schema.RepositoryID,
		RepositoryName: schema.RepositoryName,
		Domains:        schemaDomains,
	}, nil
}

// MapGrpcSchemaResponseToAgentSchema maps the gRPC schema to the agent schema.
func MapGrpcSchemaResponseToAgentSchema(schema *SchemaResponse) (*azmodels.Schema, error) {
	schemaDomains, err := MapGrpcSchemaDomainsToAgentDomains(schema.Domains)
	if err != nil {
		return nil, err
	}
	return &azmodels.Schema{
		SchemaID:       schema.SchemaID,
		CreatedAt:      schema.CreatedAt.AsTime(),
		UpdatedAt:      schema.UpdatedAt.AsTime(),
		AccountID:      schema.AccountID,
		RepositoryID:   schema.RepositoryID,
		RepositoryName: schema.RepositoryName,
		SchemaDomains: &azmodels.SchemaDomains{
			Domains: schemaDomains,
		},
	}, nil
}
