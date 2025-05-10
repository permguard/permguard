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
