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
	"fmt"
	"slices"
	"time"

	azvalidators "github.com/permguard/permguard/pkg/extensions/validators"
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

// Validate validates the schema payload.
func (s *SchemaDomains) Validate() (bool, error) {
	if isValid, err := azvalidators.ValidateInstance(s); err != nil || !isValid {
		return isValid, err
	}
	if len(s.Domains) == 0 {
		return false, fmt.Errorf("domains are required")
	}
	domains := []string{}
	for _, domain := range s.Domains {
		if slices.Contains(domains, domain.Name) {
			return false, fmt.Errorf("duplicate domain name %s", domain.Name)
		}
		domains = append(domains, domain.Name)
		if len(domain.Resources) == 0 {
			return false, fmt.Errorf("resources are required")
		}
		resources := []string{}
		for _, resource := range domain.Resources {
			if slices.Contains(resources, resource.Name) {
				return false, fmt.Errorf("duplicate resource name %s", resource.Name)
			}
			resources = append(resources, resource.Name)
			if len(resource.Actions) == 0 {
				return false, fmt.Errorf("actions are required")
			}
			actions := []string{}
			for _, action := range resource.Actions {
				if slices.Contains(actions, action.Name) {
					return false, fmt.Errorf("duplicate action name %s", action.Name)
				}
				actions = append(actions, action.Name)
			}
		}
	}
	return true, nil
}
