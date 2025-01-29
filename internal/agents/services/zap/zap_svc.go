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

	azctrlzap "github.com/permguard/permguard/internal/agents/services/zap/controllers"
	azapiv1zap "github.com/permguard/permguard/internal/agents/services/zap/endpoints/api/v1"
	azruntime "github.com/permguard/permguard/pkg/agents/runtime"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// ZAPService holds the configuration for the server.
type ZAPService struct {
	config       *ZAPServiceConfig
	configReader azruntime.ServiceConfigReader
}

// NewZAPService creates a new server  configuration.
func NewZAPService(zapServiceCfg *ZAPServiceConfig) (*ZAPService, error) {
	configReader, err := azservices.NewServiceConfiguration(zapServiceCfg.GetConfigData())
	if err != nil {
		return nil, err
	}
	return &ZAPService{
		config:       zapServiceCfg,
		configReader: configReader,
	}, nil
}

// GetService returns the service kind.
func (f *ZAPService) GetService() azservices.ServiceKind {
	return f.config.GetService()
}

// GetEndpoints returns the service kind.
func (f *ZAPService) GetEndpoints() ([]azservices.EndpointInitializer, error) {
	endpoint, err := azservices.NewEndpointInitializer(
		f.config.GetService(),
		f.config.GetPort(),
		func(grpcServer *grpc.Server, srvCtx *azservices.ServiceContext, endptCtx *azservices.EndpointContext, storageConnector *azstorage.StorageConnector) error {
			storageKind := f.config.GetStorageCentralEngine()
			centralStorage, err := storageConnector.GetCentralStorage(storageKind, endptCtx)
			if err != nil {
				return err
			}
			zapCentralStorage, err := centralStorage.GetZAPCentralStorage()
			if err != nil {
				return err
			}
			controller, err := azctrlzap.NewZAPController(srvCtx, zapCentralStorage)
			if err != nil {
				return nil
			}
			err = controller.Setup()
			if err != nil {
				return err
			}
			zapServer, err := azapiv1zap.NewV1ZAPServer(endptCtx, controller)
			azapiv1zap.RegisterV1ZAPServiceServer(grpcServer, zapServer)
			return err
		})
	if err != nil {
		return nil, err
	}
	endpoints := []azservices.EndpointInitializer{endpoint}
	return endpoints, nil
}

// GetServiceConfigReader returns the service configuration reader.
func (f *ZAPService) GetServiceConfigReader() (azruntime.ServiceConfigReader, error) {
	return f.configReader, nil
}
