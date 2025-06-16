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
	configReader, err := services.NewServiceConfiguration(papServiceCfg.ConfigData())
	if err != nil {
		return nil, err
	}
	return &PAPService{
		config:       papServiceCfg,
		configReader: configReader,
	}, nil
}

// Service returns the service kind.
func (f *PAPService) Service() services.ServiceKind {
	return f.config.Service()
}

// Endpoints returns the service kind.
func (f *PAPService) Endpoints() ([]services.EndpointInitializer, error) {
	endpoint, err := services.NewEndpointInitializer(
		f.config.Service(),
		f.config.Port(),
		func(grpcServer *grpc.Server, srvCtx *services.ServiceContext, endptCtx *services.EndpointContext, storageConnector *storage.StorageConnector) error {
			storageKind := f.config.StorageCentralEngine()
			centralStorage, err := storageConnector.CentralStorage(storageKind, endptCtx)
			if err != nil {
				return err
			}
			papCentralStorage, err := centralStorage.PAPCentralStorage()
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

// ServiceConfigReader returns the service configuration reader.
func (f *PAPService) ServiceConfigReader() (runtime.ServiceConfigReader, error) {
	return f.configReader, nil
}
