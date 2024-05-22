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
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// JSONMap is a type for JSONB data type.
type JSONMap map[string]interface{}

// Value return json value, implement driver.Valuer interface
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	data, err := j.MarshalJSON()
	return string(data), err
}

// Scan scan value into Json, implements sql.Scanner interface
func (j *JSONMap) Scan(val interface{}) error {
	var data []byte
	switch v := val.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("failed to scan value: %s", val)
	}
	jMap := map[string]interface{}{}
	err := json.Unmarshal(data, &jMap)
	*j = JSONMap(jMap)
	return err
}

// MarshalJSON to serialize to []byte.
func (j JSONMap) MarshalJSON() ([]byte, error) {
	if j == nil {
		return []byte("null"), nil
	}
	t := (map[string]interface{})(j)
	return json.Marshal(t)
}

// UnmarshalJSON to deserialize []byte.
func (j *JSONMap) UnmarshalJSON(b []byte) error {
	jMap := map[string]interface{}{}
	err := json.Unmarshal(b, &jMap)
	*j = JSONMap(jMap)
	return err
}

// GormDataType gorm data type.
func (j JSONMap) GormDataType() string {
	return "jsonmap"
}

// GormDBDataType gorm db data type.
func (JSONMap) GormDBDataType(db *gorm.DB, field *schema.Field) string {
	return "JSONB"
}
