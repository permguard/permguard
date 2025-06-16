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

package services

// ServiceFactoryProvider is the service provider.
type ServiceFactoryProvider struct {
	config      ServiceFactoryConfig
	funcSvcFact func(ServiceFactoryConfig) (ServiceFactory, error)
}

// NewServiceFactoryProvider creates a new service factory provider.
func NewServiceFactoryProvider(funcSvcFactCfg func() (ServiceFactoryConfig, error), funcSvcFact func(ServiceFactoryConfig) (ServiceFactory, error)) (*ServiceFactoryProvider, error) {
	config, err := funcSvcFactCfg()
	if err != nil {
		return nil, err
	}
	return &ServiceFactoryProvider{
		config:      config,
		funcSvcFact: funcSvcFact,
	}, nil
}

// FactoryConfig returns the factory configuration.
func (p ServiceFactoryProvider) FactoryConfig() (ServiceFactoryConfig, error) {
	return p.config, nil
}

// CreateFactory creates a new factory.
func (p ServiceFactoryProvider) CreateFactory() (ServiceFactory, error) {
	return p.funcSvcFact(p.config)
}
