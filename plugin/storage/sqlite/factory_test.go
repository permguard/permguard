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

package sqlite

import (
	"flag"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/permguard/permguard/pkg/agents/runtime/mocks"
	"github.com/permguard/permguard/pkg/agents/storage"
)

// TestSQLiteStorageFactory tests the SQLiteStorageFactory.
func TestSQLiteStorageFactory(t *testing.T) {
	assert := assert.New(t)
	storageFctyCfg, _ := NewSQLiteStorageFactoryConfig()
	assert.Nil(storageFctyCfg.AddFlags(&flag.FlagSet{}), "error should be nil")
	assert.Nil(storageFctyCfg.InitFromViper(&viper.Viper{}), "error should be nil")

	storageFcty, err := NewSQLiteStorageFactory(nil)
	assert.Nil(storageFcty, "storage factory should be nil")
	assert.NotNil(err, "error should not be nil")

	storageFcty, _ = NewSQLiteStorageFactory(storageFctyCfg)

	runtimeCtx := mocks.NewRuntimeContextMock(nil, nil)
	storageCtx, err := storage.NewStorageContext(runtimeCtx, storage.StorageSQLite)
	if err != nil {
		t.Fatal(err)
	}

	centralstorage, err := storageFcty.CreateCentralStorage(storageCtx)
	assert.NotNil(centralstorage, "central storage should not be nil")
	assert.Nil(err, "error should be nil")

	centralZAPStorage, err := centralstorage.ZAPCentralStorage()
	assert.NotNil(centralZAPStorage, "central ZAP storage should not be nil")
	assert.Nil(err, "error should be nil")

	centralPAPStorage, err := centralstorage.PAPCentralStorage()
	assert.NotNil(centralPAPStorage, "central ZAP storage should not be nil")
	assert.Nil(err, "error should be nil")

}
