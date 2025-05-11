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

package pdp

import (
	"google.golang.org/grpc"

	pdpctrl "github.com/permguard/permguard/internal/agents/services/pdp/controllers"
	pdpv1 "github.com/permguard/permguard/internal/agents/services/pdp/endpoints/api/v1"
	"github.com/permguard/permguard/pkg/agents/runtime"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
)

// PDPService holds the configuration for the server.
type PDPService struct {
	config       *PDPServiceConfig
	configReader runtime.ServiceConfigReader
}

// NewPDPService creates a new server  configuration.
func NewPDPService(pdpServiceCfg *PDPServiceConfig) (*PDPService, error) {
	configReader, err := services.NewServiceConfiguration(pdpServiceCfg.GetConfigData())
	if err != nil {
		return nil, err
	}
	return &PDPService{
		config:       pdpServiceCfg,
		configReader: configReader,
	}, nil
}

// GetService returns the service kind.
func (f *PDPService) GetService() services.ServiceKind {
	return f.config.GetService()
}

// GetEndpoints returns the service kind.
func (f *PDPService) GetEndpoints() ([]services.EndpointInitializer, error) {
	endpoint, err := services.NewEndpointInitializer(
		f.config.GetService(),
		f.config.GetPort(),
		func(grpcServer *grpc.Server, srvCtx *services.ServiceContext, endptCtx *services.EndpointContext, storageConnector *storage.StorageConnector) error {
			storageKind := f.config.GetStorageCentralEngine()
			centralStorage, err := storageConnector.GetCentralStorage(storageKind, endptCtx)
			if err != nil {
				return err
			}
			pdpCentralStorage, err := centralStorage.GetPDPCentralStorage()
			if err != nil {
				return err
			}
			controller, err := pdpctrl.NewPDPController(srvCtx, pdpCentralStorage)
			if err != nil {
				return nil
			}
			err = controller.Setup()
			if err != nil {
				return err
			}
			pdpServer, err := pdpv1.NewV1PDPServer(endptCtx, controller)
			pdpv1.RegisterV1PDPServiceServer(grpcServer, pdpServer)
			return err
		})
	if err != nil {
		return nil, err
	}
	endpoints := []services.EndpointInitializer{endpoint}
	return endpoints, nil
}

// GetServiceConfigReader returns the service configuration reader.
func (f *PDPService) GetServiceConfigReader() (runtime.ServiceConfigReader, error) {
	return f.configReader, nil
}
