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

// FactoryProvider is the storage provider.
type FactoryProvider struct {
	config      FactoryConfig
	funcSvcFact func(FactoryConfig) (Factory, error)
}

// NewStorageFactoryProvider creates a new storage factory provider.
func NewStorageFactoryProvider(funcSvcFactCfg func() (FactoryConfig, error), funcSvcFact func(FactoryConfig) (Factory, error)) (*FactoryProvider, error) {
	config, err := funcSvcFactCfg()
	if err != nil {
		return nil, err
	}
	return &FactoryProvider{
		config:      config,
		funcSvcFact: funcSvcFact,
	}, nil
}

// FactoryConfig returns the factory configuration.
func (p FactoryProvider) FactoryConfig() (FactoryConfig, error) {
	return p.config, nil
}

// CreateFactory creates a new factory.
func (p FactoryProvider) CreateFactory() (Factory, error) {
	return p.funcSvcFact(p.config)
}
