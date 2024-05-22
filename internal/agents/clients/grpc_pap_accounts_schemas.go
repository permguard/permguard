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

package grpcclients

import (
	"context"
	"fmt"

	azapiv1pap "github.com/permguard/permguard/internal/agents/services/pap/endpoints/api/v1"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// CreateSchema creates a new schema.
func (c *GrpcPAPClient) upsert(isCreate bool, schema *azmodels.Schema) (*azmodels.Schema, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	schemaDomains, err := azapiv1pap.MapAgentDomainToGrpcSchemaDomains(schema.SchemaDomains.Domains)
	if err != nil {
		return nil, err
	}
	var schemaResponse *azapiv1pap.SchemaResponse
	if isCreate {
		return nil, fmt.Errorf("clients: create is not implemented")
	} else {
		schemaResponse, err = client.UpdateSchema(context.Background(), &azapiv1pap.SchemaUpdateRequest{
			SchemaID:     &schema.SchemaID,
			AccountID:    schema.AccountID,
			RepositoryID: &schema.RepositoryID,
			Domains:      schemaDomains,
		})
	}
	if err != nil {
		return nil, err
	}
	schemaResponseDomains, err := azapiv1pap.MapGrpcSchemaDomainsToAgentDomains(schemaResponse.Domains)
	if err != nil {
		return nil, err
	}
	return &azmodels.Schema{
		SchemaID:     schemaResponse.SchemaID,
		CreatedAt:    schemaResponse.CreatedAt.AsTime(),
		UpdatedAt:    schemaResponse.UpdatedAt.AsTime(),
		AccountID:    schemaResponse.AccountID,
		RepositoryID: schemaResponse.RepositoryID,
		SchemaDomains: &azmodels.SchemaDomains{
			Domains: schemaResponseDomains,
		},
	}, nil
}

// UpdateSchema updates a schema.
func (c *GrpcPAPClient) UpdateSchema(schema *azmodels.Schema) (*azmodels.Schema, error) {
	return c.upsert(false, schema)
}

// GetAllSchemas returns all the Schemas.
func (c *GrpcPAPClient) GetAllSchemas(accountID int64) ([]azmodels.Schema, error) {
	return c.GetSchemasBy(accountID, "")
}

// GetSchemasByAccountID returns all Schemas filtering by account id.
func (c *GrpcPAPClient) GetSchemasByAccountID(accountID int64) ([]azmodels.Schema, error) {
	return c.GetSchemasBy(accountID, "")
}

// GetSchemasBySchemaID returns all Schemas filtering by schema id.
func (c *GrpcPAPClient) GetSchemasBySchemaID(schemaID string) ([]azmodels.Schema, error) {
	return c.GetSchemasBy(0, schemaID)
}

// GetSchemasBy returns all Schemas filtering by Schema id and name.
func (c *GrpcPAPClient) GetSchemasBy(accountID int64, schemaID string) ([]azmodels.Schema, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	schemaGetRequest := &azapiv1pap.SchemaGetRequest{}
	if accountID > 0 {
		schemaGetRequest.AccountID = accountID
	}
	if schemaID != "" {
		schemaGetRequest.SchemaID = &schemaID
	}
	schemaList, err := client.GetAllSchemas(context.Background(), schemaGetRequest)
	if err != nil {
		return nil, err
	}
	schemas := make([]azmodels.Schema, len(schemaList.Schemas))
	for i, schema := range schemaList.Schemas {
		schema, err := azapiv1pap.MapGrpcSchemaResponseToAgentSchema(schema)
		if err != nil {
			return nil, err
		}
		schemas[i] = *schema
	}
	return schemas, nil
}
