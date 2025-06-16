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

package centralstorage

import (
	"fmt"

	"github.com/permguard/permguard/pkg/agents/runtime"
	"github.com/permguard/permguard/pkg/agents/storage"
)

const (
	// enabledDefaultCreationKey is the key for the flag to enable the creation of default entities.
	enabledDefaultCreationKey = "data-enable-default-creation"
	// enabledDefaultCreationDefault is the default value for the flag to enable the creation of default entities.
	enabledDefaultCreationDefault = false
	// maxPageSizeKey is the key for the maximum number of items to fetch per request.
	maxPageSizeKey = "data-fetch-maxpagesize"
	// maxPageSizeDefault is the default value for the maximum number of items to fetch per request.
	maxPageSizeDefault = 10000
)

// SQLiteCentralStorageConfig is the SQLite central storage configuration.
type SQLiteCentralStorageConfig struct {
	configReader runtime.ServiceConfigReader
}

// NewSQLiteCentralStorageConfig creates a new SQLite central storage configuration.
func NewSQLiteCentralStorageConfig(ctx *storage.StorageContext) (*SQLiteCentralStorageConfig, error) {
	if ctx == nil {
		return nil, fmt.Errorf("storage: invalid storage context")
	}
	cgfReader, err := ctx.ServiceConfigReader()
	if err != nil {
		return nil, fmt.Errorf("storage: unable to get service config reader: %w", err)
	}
	return &SQLiteCentralStorageConfig{
		configReader: cgfReader,
	}, nil
}

// DataFetchMaxPageSize returns the maximum number of items to fetch per request.
func (c *SQLiteCentralStorageConfig) DataFetchMaxPageSize() int32 {
	maxSize, err := c.configReader.Value(maxPageSizeKey)
	if err != nil {
		return 10000
	}
	if intValue, ok := maxSize.(int32); ok {
		return intValue
	}
	return maxPageSizeDefault
}

// EnabledDefaultCreation returns the flag to enable the creation of default entities.
func (c *SQLiteCentralStorageConfig) EnabledDefaultCreation() bool {
	enableDefaultCreation, err := c.configReader.Value(enabledDefaultCreationKey)
	if err != nil {
		return false
	}
	if boolValue, ok := enableDefaultCreation.(bool); ok {
		return boolValue
	}
	return enabledDefaultCreationDefault
}
