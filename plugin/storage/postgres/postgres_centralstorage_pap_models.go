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
	"time"

	"github.com/google/uuid"
)

// Repository is the model for the schema table.
type Repository struct {
	RepositoryID uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4()"`
	CreatedAt    time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt    time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	AccountID    int64     `gorm:"uniqueIndex:repositories_account_id_idx"`
	Name         string    `gorm:"type:varchar(254);uniqueIndex:repositories_name_idx"`
}

// Schema is the model for the schema table.
type Schema struct {
	SchemaID     uuid.UUID  `gorm:"type:uuid;default:uuid_generate_v4()"`
	CreatedAt    time.Time  `gorm:"default:CURRENT_TIMESTAMP"`
	UpdatedAt    time.Time  `gorm:"default:CURRENT_TIMESTAMP"`
	AccountID    int64      `gorm:"uniqueIndex:schemas_account_id_idx"`
	RepositoryID uuid.UUID  `gorm:"uniqueIndex:schemas_account_repository_id_idx"`
	Repository   Repository `gorm:"foreignKey:RepositoryID;references:repository_id"`
	Domains      JSONMap    `gorm:"type:jsonb"`
}
