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

package storage

// StorageFactoryProvider is the storage provider.
type StorageFactoryProvider struct {
	config      StorageFactoryConfig
	funcSvcFact func(StorageFactoryConfig) (StorageFactory, error)
}

// NewStorageFactoryProvider creates a new storage factory provider.
func NewStorageFactoryProvider(funcSvcFactCfg func() (StorageFactoryConfig, error), funcSvcFact func(StorageFactoryConfig) (StorageFactory, error)) (*StorageFactoryProvider, error) {
	config, err := funcSvcFactCfg()
	if err != nil {
		return nil, err
	}
	return &StorageFactoryProvider{
		config:      config,
		funcSvcFact: funcSvcFact,
	}, nil
}

// FactoryConfig returns the factory configuration.
func (p StorageFactoryProvider) FactoryConfig() (StorageFactoryConfig, error) {
	return p.config, nil
}

// CreateFactory creates a new factory.
func (p StorageFactoryProvider) CreateFactory() (StorageFactory, error) {
	return p.funcSvcFact(p.config)
}
