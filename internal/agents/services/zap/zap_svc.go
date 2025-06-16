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

package zap

import (
	"google.golang.org/grpc"

	zapctrl "github.com/permguard/permguard/internal/agents/services/zap/controllers"
	zapv1 "github.com/permguard/permguard/internal/agents/services/zap/endpoints/api/v1"
	"github.com/permguard/permguard/pkg/agents/runtime"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
)

// ZAPService holds the configuration for the server.
type ZAPService struct {
	config       *ZAPServiceConfig
	configReader runtime.ServiceConfigReader
}

// NewZAPService creates a new server  configuration.
func NewZAPService(zapServiceCfg *ZAPServiceConfig) (*ZAPService, error) {
	configReader, err := services.NewServiceConfiguration(zapServiceCfg.ConfigData())
	if err != nil {
		return nil, err
	}
	return &ZAPService{
		config:       zapServiceCfg,
		configReader: configReader,
	}, nil
}

// Service returns the service kind.
func (f *ZAPService) Service() services.ServiceKind {
	return f.config.Service()
}

// Endpoints returns the service kind.
func (f *ZAPService) Endpoints() ([]services.EndpointInitializer, error) {
	endpoint, err := services.NewEndpointInitializer(
		f.config.Service(),
		f.config.Port(),
		func(grpcServer *grpc.Server, srvCtx *services.ServiceContext, endptCtx *services.EndpointContext, storageConnector *storage.StorageConnector) error {
			storageKind := f.config.StorageCentralEngine()
			centralStorage, err := storageConnector.CentralStorage(storageKind, endptCtx)
			if err != nil {
				return err
			}
			zapCentralStorage, err := centralStorage.ZAPCentralStorage()
			if err != nil {
				return err
			}
			controller, err := zapctrl.NewZAPController(srvCtx, zapCentralStorage)
			if err != nil {
				return nil
			}
			err = controller.Setup()
			if err != nil {
				return err
			}
			zapServer, err := zapv1.NewV1ZAPServer(endptCtx, controller)
			zapv1.RegisterV1ZAPServiceServer(grpcServer, zapServer)
			return err
		})
	if err != nil {
		return nil, err
	}
	endpoints := []services.EndpointInitializer{endpoint}
	return endpoints, nil
}

// ServiceConfigReader returns the service configuration reader.
func (f *ZAPService) ServiceConfigReader() (runtime.ServiceConfigReader, error) {
	return f.configReader, nil
}
