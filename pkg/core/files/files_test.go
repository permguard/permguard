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

package files

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCheckPathIfExists(t *testing.T) {
	assert := assert.New(t)

	folderName := filepath.Join(".tmp", uuid.NewString())
	err := os.MkdirAll(folderName, 0755)
	assert.Nil(err)

	existingFile := filepath.Join(folderName, "existing_file.txt")
	nonExistingFile := filepath.Join(folderName, "non_existing_file.txt")

	// Create an existing file
	file, err := os.Create(existingFile)
	assert.Nil(err)
	file.Close()

	// Test with existing file
	exists, err := CheckPathIfExists(existingFile)
	assert.Nil(err)
	assert.True(exists)

	// Test with non-existing file
	exists, err = CheckPathIfExists(nonExistingFile)
	assert.Nil(err)
	assert.False(exists)

	// Clean up the test folder
	err = os.RemoveAll(folderName)
	assert.Nil(err)
}

func TestCreateFileIfNotExists(t *testing.T) {
	assert := assert.New(t)

	folderName := filepath.Join(".tmp", uuid.NewString())
	err := os.MkdirAll(folderName, 0755)
	assert.Nil(err)

	fileName := filepath.Join(folderName, "new_file.txt")

	// Test creating a new file
	created, err := CreateFileIfNotExists(fileName)
	assert.Nil(err)
	assert.True(created)

	// Test with existing file
	created, err = CreateFileIfNotExists(fileName)
	assert.Nil(err)
	assert.False(created)

	// Clean up the test folder
	err = os.RemoveAll(folderName)
	assert.Nil(err)
}

func TestCreateDirIfNotExists(t *testing.T) {
	assert := assert.New(t)

	folderName := filepath.Join(".tmp", uuid.NewString())

	// Test creating a new directory
	created, err := CreateDirIfNotExists(folderName)
	assert.Nil(err)
	assert.True(created)

	// Test with existing directory
	created, err = CreateDirIfNotExists(folderName)
	assert.Nil(err)
	assert.False(created)

	// Clean up the test folder
	err = os.RemoveAll(folderName)
	assert.Nil(err)
}

func TestWriteFileIfNotExists(t *testing.T) {
	assert := assert.New(t)

	folderName := filepath.Join(".tmp", uuid.NewString())
	err := os.MkdirAll(folderName, 0755)
	assert.Nil(err)

	fileName := filepath.Join(folderName, "new_file.txt")
	data := []byte("Hello, World!")

	// Test writing a new file
	written, err := WriteFileIfNotExists(fileName, data, 0644, false)
	assert.Nil(err)
	assert.True(written)

	// Test with existing file
	written, err = WriteFileIfNotExists(fileName, data, 0644, false)
	assert.Nil(err)
	assert.False(written)

	// Clean up the test folder
	err = os.RemoveAll(folderName)
	assert.Nil(err)
}

func TestAppendToFile(t *testing.T) {
	assert := assert.New(t)

	folderName := filepath.Join(".tmp", uuid.NewString())
	err := os.MkdirAll(folderName, 0755)
	assert.Nil(err)

	fileName := filepath.Join(folderName, "append_file.txt")
	data := []byte("Hello, World!\n")

	// Create the file and append data
	written, err := AppendToFile(fileName, data, false)
	assert.Nil(err)
	assert.True(written)

	// Append more data
	written, err = AppendToFile(fileName, []byte("Another line\n"), false)
	assert.Nil(err)
	assert.True(written)

	// Clean up the test folder
	err = os.RemoveAll(folderName)
	assert.Nil(err)
}

func TestReadTOMLFile(t *testing.T) {
	assert := assert.New(t)

	folderName := filepath.Join(".tmp", uuid.NewString())
	err := os.MkdirAll(folderName, 0755)
	assert.Nil(err)

	fileName := filepath.Join(folderName, "config.toml")
	data := []byte(`
name = "test"
age = 30
`)

	// Write the TOML file
	_, err = WriteFile(fileName, data, 0644, false)
	assert.Nil(err)

	// Define a structure to read the TOML data
	var config struct {
		Name string
		Age  int
	}

	// Read the TOML file
	err = ReadTOMLFile(fileName, &config)
	assert.Nil(err)
	assert.Equal("test", config.Name)
	assert.Equal(30, config.Age)

	// Clean up the test folder
	err = os.RemoveAll(folderName)
	assert.Nil(err)
}
