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

package models

import (
	"time"
)

const (
	FieldRepositoryAccountID    = "account_id"
	FieldRepositoryRepositoryID = "repository_id"
	FieldRepositoryName         = "name"
	FieldSchemaSchemaID         = "schema_id"
	FieldSchemaAccountID        = "account_id"
)

// Repository is the repository.
type Repository struct {
	RepositoryID string    `json:"repository_id" validate:"required,isuuid"`
	CreatedAt    time.Time `json:"created_at" validate:"required"`
	UpdatedAt    time.Time `json:"updated_at" validate:"required"`
	AccountID    int64     `json:"account_id" validate:"required,gt=0"`
	Name         string    `json:"name"`
	Ref          string    `json:"ref"`
}

// Schema is the schema.
type Schema struct {
	SchemaID       string         `json:"schema_id" validate:"required,isuuid"`
	CreatedAt      time.Time      `json:"created_at" validate:"required"`
	UpdatedAt      time.Time      `json:"updated_at" validate:"required"`
	AccountID      int64          `json:"account_id" validate:"required,gt=0"`
	RepositoryID   string         `json:"repository_id" validate:"required,isuuid"`
	RepositoryName string         `json:"repository_name"`
	SchemaDomains  *SchemaDomains `json:"domains" validate:"required"`
}

// Action is the action.
type Action struct {
	Name        string `json:"name" yaml:"name" validate:"required"`
	Description string `json:"description" yaml:"description"`
}

// Resource is the resource.
type Resource struct {
	Name        string   `json:"name" yaml:"name" validate:"required"`
	Description string   `json:"description" yaml:"description"`
	Actions     []Action `json:"actions" yaml:"actions" validate:"required"`
}

// Domain is the domain.
type Domain struct {
	Name        string     `json:"name" yaml:"name" validate:"required"`
	Description string     `json:"description" yaml:"description"`
	Resources   []Resource `json:"resources" yaml:"resources" validate:"required"`
}

// SchemaDomains is the schema domains.
type SchemaDomains struct {
	Domains []Domain `json:"domains" yaml:"domains"`
}
