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

package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azcopier "github.com/permguard/permguard/pkg/extensions/copier"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// createSchema creates a schmea
func (s PostgresCentralStoragePAP) createSchema(db *gorm.DB, accountID int64, respositoryID uuid.UUID) (*azmodels.Schema, error) {
	if err := validateAccountID("schema", accountID); err != nil {
		return nil, fmt.Errorf("storage: invalid schema id %d. %w", accountID, azerrors.ErrClientAccountID)
	}
	var dbSchema Schema
	var result *gorm.DB
	dbSchema = Schema{
		AccountID:    accountID,
		RepositoryID: respositoryID,
	}
	result = db.Omit("CreatedAt", "UpdatedAt", "Domains").Create(&dbSchema)
	if result.RowsAffected == 0 || result.Error != nil {
		pgErr, ok := result.Error.(*pgconn.PgError)
		if ok && pgErr.Code == "23505" {
			return nil, fmt.Errorf("storage: schema cannot be created because of a duplicated name %w", azerrors.ErrStorageDuplicate)
		}
		return nil, fmt.Errorf("storage: schema cannot be created. %w", azerrors.ErrStorageGeneric)
	}
	return mapSchemaToAgentSchema(&dbSchema)
}

// updateSchema updates a schmea
func (s PostgresCentralStoragePAP) updateSchema(db *gorm.DB, schema *azmodels.Schema) (*azmodels.Schema, error) {
	if schema == nil {
		return nil, fmt.Errorf("storage: %w", azerrors.ErrInvalidInputParameter)
	}
	if err := validateAccountID("schema", schema.AccountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", schema.AccountID, azerrors.ErrClientAccountID)
	}
	hasSchemaID := true
	if err := validateUUID("schema", schema.SchemaID); err != nil {
		if err := validateUUID("schema", schema.RepositoryID); err != nil {
			return nil, fmt.Errorf("storage: invalid schema id %q. %w", schema.SchemaID, azerrors.ErrClientUUID)
		}
		hasSchemaID = false
	}
	var dbSchema Schema
	var result *gorm.DB
	domains := schema.SchemaDomains
	if isValid, err := domains.Validate(); err != nil || !isValid {
		return nil, fmt.Errorf("storage: invalid schema payload. %w", azerrors.ErrClientGeneric)
	}
	domainMap, err := azcopier.ConvertStructToMap(domains)
	if err != nil {
		return nil, fmt.Errorf("storage: schema payload is not valid. %w", azerrors.ErrClientGeneric)
	}
	if hasSchemaID {
		result = db.Where("account_id = ?", schema.AccountID).Where("schema_id = ?", schema.SchemaID).First(&dbSchema)
	} else {
		result = db.Where("account_id = ?", schema.AccountID).Where("repository_id = ?", schema.RepositoryID).First(&dbSchema)
	}
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("storage: schema cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	dbSchema.Domains = JSONMap(domainMap)
	result = db.Where("account_id = ?", dbSchema.AccountID).Where("schema_id = ?", dbSchema.SchemaID).Omit("CreatedAt", "UpdatedAt").Updates(&dbSchema)
	if result.RowsAffected == 0 || result.Error != nil {
		pgErr, ok := result.Error.(*pgconn.PgError)
		if ok && pgErr.Code == "23505" {
			return nil, fmt.Errorf("storage: schema cannot be updated because of a duplicated fields %w", azerrors.ErrStorageDuplicate)
		}
		return nil, fmt.Errorf("storage: schema cannot be updated. %w", azerrors.ErrStorageGeneric)
	}
	return mapSchemaToAgentSchema(&dbSchema)
}

// UpdateSchema updates a schema.
func (s PostgresCentralStoragePAP) UpdateSchema(schema *azmodels.Schema) (*azmodels.Schema, error) {
	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}
	return s.updateSchema(db, schema)
}

// GetAllSchemas gets all schemas.
func (s PostgresCentralStoragePAP) GetAllSchemas(accountID int64, fields map[string]any) ([]azmodels.Schema, error) {
	if err := validateAccountID("schema", accountID); err != nil {
		return nil, fmt.Errorf("storage: invalid account id %d. %w", accountID, azerrors.ErrClientAccountID)
	}

	logger := s.ctx.GetLogger()
	db, err := s.connection.Connect(logger, context.Background())
	if err != nil {
		return nil, fmt.Errorf("storage: cannot connect to postgres. %w", azerrors.ErrServerInfrastructure)
	}

	var dbSchemas []Schema
	query := db.Where("account_id = ?", accountID)
	if _, ok := fields[azmodels.FieldSchemaSchemaID]; ok {
		schemaid, ok := fields[azmodels.FieldSchemaSchemaID].(string)
		if !ok {
			return nil, fmt.Errorf("storage: invalid repository id. %w", azerrors.ErrClientUUID)
		}
		if err := validateUUID("schema", schemaid); err != nil {
			return nil, fmt.Errorf("storage: invalid schema id %q. %w", schemaid, azerrors.ErrClientUUID)
		}
		schemaid = "%" + schemaid + "%"
		query = query.Where("schema_id::text LIKE ?", schemaid)
	}
	result := query.Preload("Repository").Find(&dbSchemas)
	if result.Error != nil {
		return nil, fmt.Errorf("storage: repository cannot be retrieved. %w", azerrors.ErrStorageNotFound)
	}
	shemas := make([]azmodels.Schema, len(dbSchemas))
	for i, s := range dbSchemas {
		schema, err := mapSchemaToAgentSchema(&s)
		schema.RepositoryName = s.Repository.Name
		if err != nil {
			return nil, err
		}
		shemas[i] = *schema
	}
	return shemas, nil
}
