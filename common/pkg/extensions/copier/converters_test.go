// Copyright 2025 Nitro Agility S.r.l.
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

package copier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertStructToMap(t *testing.T) {
	assert := assert.New(t)

	// Define a struct for testing
	type Person struct {
		Name string
		Age  int
	}

	// Test 1: Convert a struct to a map
	person := Person{Name: "John", Age: 30}
	resultMap, err := ConvertStructToMap(person)
	assert.Nil(err)
	assert.Equal("John", resultMap["Name"])
	assert.Equal(30, int(resultMap["Age"].(float64))) // JSON Unmarshal converts numbers to float64 by default

	// Test 2: Convert an empty struct to a map
	emptyPerson := Person{}
	resultMap, err = ConvertStructToMap(emptyPerson)
	assert.Nil(err)
	assert.Equal("", resultMap["Name"])
	assert.Equal(0, int(resultMap["Age"].(float64)))
}

func TestConvertMapToStruct(t *testing.T) {
	assert := assert.New(t)

	// Define a struct for testing
	type Person struct {
		Name string
		Age  int
	}

	// Test 1: Convert a map to a struct
	personMap := map[string]any{"Name": "John", "Age": 30}
	var person Person
	err := ConvertMapToStruct(personMap, &person)
	assert.Nil(err)
	assert.Equal("John", person.Name)
	assert.Equal(30, person.Age)

	// Test 2: Convert an empty map to a struct
	emptyMap := map[string]any{}
	var emptyPerson Person
	err = ConvertMapToStruct(emptyMap, &emptyPerson)
	assert.Nil(err)
	assert.Equal("", emptyPerson.Name)
	assert.Equal(0, emptyPerson.Age)
}
