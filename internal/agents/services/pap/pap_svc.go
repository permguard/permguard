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

package pap

import (
	"google.golang.org/grpc"

	papctrl "github.com/permguard/permguard/internal/agents/services/pap/controllers"
	papv1 "github.com/permguard/permguard/internal/agents/services/pap/endpoints/api/v1"
	"github.com/permguard/permguard/pkg/agents/runtime"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
)

// PAPService holds the configuration for the server.
type PAPService struct {
	config       *PAPServiceConfig
	configReader runtime.ServiceConfigReader
}

// NewPAPService creates a new server  configuration.
func NewPAPService(papServiceCfg *PAPServiceConfig) (*PAPService, error) {
	configReader, err := services.NewServiceConfiguration(papServiceCfg.GetConfigData())
	if err != nil {
		return nil, err
	}
	return &PAPService{
		config:       papServiceCfg,
		configReader: configReader,
	}, nil
}

// GetService returns the service kind.
func (f *PAPService) GetService() services.ServiceKind {
	return f.config.GetService()
}

// GetEndpoints returns the service kind.
func (f *PAPService) GetEndpoints() ([]services.EndpointInitializer, error) {
	endpoint, err := services.NewEndpointInitializer(
		f.config.GetService(),
		f.config.GetPort(),
		func(grpcServer *grpc.Server, srvCtx *services.ServiceContext, endptCtx *services.EndpointContext, storageConnector *storage.StorageConnector) error {
			storageKind := f.config.GetStorageCentralEngine()
			centralStorage, err := storageConnector.GetCentralStorage(storageKind, endptCtx)
			if err != nil {
				return err
			}
			papCentralStorage, err := centralStorage.GetPAPCentralStorage()
			if err != nil {
				return err
			}
			controller, err := papctrl.NewPAPController(srvCtx, papCentralStorage)
			if err != nil {
				return nil
			}
			err = controller.Setup()
			if err != nil {
				return err
			}
			papServer, err := papv1.NewV1PAPServer(endptCtx, controller)
			papv1.RegisterV1PAPServiceServer(grpcServer, papServer)
			return err
		})
	if err != nil {
		return nil, err
	}
	endpoints := []services.EndpointInitializer{endpoint}
	return endpoints, nil
}

// GetServiceConfigReader returns the service configuration reader.
func (f *PAPService) GetServiceConfigReader() (runtime.ServiceConfigReader, error) {
	return f.configReader, nil
}
