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
	"reflect"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// TestJSONMapValue tests the Value method of the JSONMap type.
func TestJSONMapValue(t *testing.T) {
	// Create a JSONMap instance
	j := JSONMap{
		"key1": "value1",
		"key2": 123,
	}

	// Call the Value method
	_, err := j.Value()

	// Check if the error is nil
	if err != nil {
		t.Errorf("Value method should not return an error, got %v", err)
	}
}

// TestJSONMapScan tests the Scan method of the JSONMap type.
func TestJSONMapScan(t *testing.T) {
	// Create a JSONMap instance
	j := JSONMap{}

	// Define a sample JSON string
	jsonStr := `{"key1": "value1", "key2": 123}`

	// Call the Scan method
	err := j.Scan([]byte(jsonStr))

	// Check if there is no error
	if err != nil {
		t.Errorf("Scan method should not return an error, got %v", err)
	}

	// Check if the JSONMap is correctly populated
	expected := JSONMap{
		"key1": "value1",
		"key2": float64(123),
	}
	if !reflect.DeepEqual(j, expected) {
		t.Errorf("Scan method did not populate JSONMap correctly, got %v", j)
	}
}
// TestJSONMapMarshalJSON tests the MarshalJSON method of the JSONMap type.
func TestJSONMapMarshalJSON(t *testing.T) {
	// Create a JSONMap instance
	j := JSONMap{
		"key1": "value1",
		"key2": 123,
	}

	// Call the MarshalJSON method
	data, err := j.MarshalJSON()

	// Check if there is no error
	if err != nil {
		t.Errorf("MarshalJSON method should not return an error, got %v", err)
	}

	// Check if the marshaled JSON data is correct
	expected := `{"key1":"value1","key2":123}`
	if string(data) != expected {
		t.Errorf("MarshalJSON method did not produce the expected JSON data, got %s", string(data))
	}
}
// TestJSONMapUnmarshalJSON tests the UnmarshalJSON method of the JSONMap type.
func TestJSONMapUnmarshalJSON(t *testing.T) {
	// Create a JSONMap instance
	j := JSONMap{}

	// Define a sample JSON string
	jsonStr := `{"key1": "value1", "key2": 123}`

	// Call the UnmarshalJSON method
	err := j.UnmarshalJSON([]byte(jsonStr))

	// Check if there is no error
	if err != nil {
		t.Errorf("UnmarshalJSON method should not return an error, got %v", err)
	}

	// Check if the JSONMap is correctly populated
	expected := JSONMap{
		"key1": "value1",
		"key2": float64(123),
	}
	if !reflect.DeepEqual(j, expected) {
		t.Errorf("UnmarshalJSON method did not populate JSONMap correctly, got %v", j)
	}
}
// TestGormDataType tests the GormDataType method of the JSONMap type.
func TestGormDataType(t *testing.T) {
	// Create a JSONMap instance
	j := JSONMap{}

	// Call the GormDataType method
	dataType := j.GormDataType()

	// Check if the data type is correct
	expected := "jsonmap"
	if dataType != expected {
		t.Errorf("GormDataType method did not return the expected data type, got %s", dataType)
	}
}
// TestGormDBDataType tests the GormDBDataType method of the JSONMap type.
func TestGormDBDataType(t *testing.T) {
	// Create a JSONMap instance
	j := JSONMap{}

	// Create a mock Gorm DB
	db := &gorm.DB{}

	// Create a mock schema field
	field := &schema.Field{}

	// Call the GormDBDataType method
	dataType := j.GormDBDataType(db, field)

	// Check if the data type is correct
	expected := "JSONB"
	if dataType != expected {
		t.Errorf("GormDBDataType method did not return the expected data type, got %s", dataType)
	}
}
