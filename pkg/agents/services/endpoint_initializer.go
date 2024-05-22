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

import (
	"google.golang.org/grpc"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// EndpointInitializer is the service endpoint factory.
type EndpointInitializer struct {
	service      ServiceKind
	port         int
	registration func(*grpc.Server, *ServiceContext, *EndpointContext, *azstorage.StorageConnector) error
}

// NewEndpointInitializer creates a new service endpoint factory.
func NewEndpointInitializer(service ServiceKind, port int, registration func(*grpc.Server, *ServiceContext, *EndpointContext, *azstorage.StorageConnector) error) (EndpointInitializer, error) {
	return EndpointInitializer{
		service:      service,
		port:         port,
		registration: registration,
	}, nil
}

// GetService returns the service kind.
func (d EndpointInitializer) GetService() ServiceKind {
	return d.service
}

// GetPort returns the port.
func (d EndpointInitializer) GetPort() int {
	return d.port
}

// GetRegistration returns the registration.
func (d EndpointInitializer) GetRegistration() func(*grpc.Server, *ServiceContext, *EndpointContext, *azstorage.StorageConnector) error {
	return d.registration
}
