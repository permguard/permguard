package copier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCopySlice(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Copy an empty slice
	originalSlice := []int{}
	copiedSlice := CopySlice(originalSlice)
	assert.Equal(originalSlice, copiedSlice)

	// Test 2: Copy a non-empty slice
	originalSlice = []int{1, 2, 3, 4}
	copiedSlice = CopySlice(originalSlice)
	assert.Equal(originalSlice, copiedSlice)

	// Modify the original slice and verify the copied slice is not affected
	originalSlice[0] = 100
	assert.NotEqual(originalSlice, copiedSlice)
}

func TestCopyMap(t *testing.T) {
	assert := assert.New(t)

	// Test 1: Copy an empty map
	originalMap := map[string]int{}
	copiedMap := CopyMap(originalMap)
	assert.Equal(originalMap, copiedMap)

	// Test 2: Copy a non-empty map
	originalMap = map[string]int{"a": 1, "b": 2}
	copiedMap = CopyMap(originalMap)
	assert.Equal(originalMap, copiedMap)

	// Modify the original map and verify the copied map is not affected
	originalMap["a"] = 100
	assert.NotEqual(originalMap, copiedMap)
}

func TestCopy(t *testing.T) {
	assert := assert.New(t)

	// Define two structs to test copying
	type Person struct {
		Name string
		Age  int
	}

	// Test 1: Copy struct fields from one struct to another
	from := Person{Name: "John", Age: 30}
	to := Person{}

	err := Copy(&to, &from)
	assert.Nil(err)
	assert.Equal(from, to)

	// Modify the original struct and verify the copied struct is not affected
	from.Name = "Jane"
	assert.NotEqual(from, to)
}
