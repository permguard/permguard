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

	azruntime "github.com/permguard/permguard/pkg/agents/runtime"
	azctrlpap "github.com/permguard/permguard/internal/agents/services/pap/controllers"
	azapiv1pap "github.com/permguard/permguard/internal/agents/services/pap/endpoints/api/v1"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// PAPService holds the configuration for the server.
type PAPService struct {
	config			*PAPServiceConfig
	configReader	azruntime.ServiceConfigReader
}

// NewPAPService creates a new server  configuration.
func NewPAPService(papServiceCfg *PAPServiceConfig) (*PAPService, error) {
	configReader, err := azservices.NewServiceConfiguration(papServiceCfg.GetConfigData())
	if err != nil {
		return nil, err
	}
	return &PAPService{
		config: papServiceCfg,
		configReader: configReader,
	}, nil
}

// GetService returns the service kind.
func (f *PAPService) GetService() azservices.ServiceKind {
	return f.config.GetService()
}

// GetEndpoints returns the service kind.
func (f *PAPService) GetEndpoints() ([]azservices.EndpointInitializer, error) {
	endpoint, err := azservices.NewEndpointInitializer(
		f.config.GetService(),
		f.config.GetPort(),
		func(grpcServer *grpc.Server, srvCtx *azservices.ServiceContext, endptCtx *azservices.EndpointContext, storageConnector *azstorage.StorageConnector) error {
			centralStorage, err := storageConnector.GetCentralStorage(endptCtx)
			if err != nil {
				return err
			}
			papCentralStorage, err := centralStorage.GetPAPCentralStorage()
			if err != nil {
				return err
			}
			controller, err := azctrlpap.NewPAPController(srvCtx, papCentralStorage)
			if err != nil {
				return nil
			}
			err = controller.Setup()
			if err != nil {
				return err
			}
			papServer, err := azapiv1pap.NewV1PAPServer(endptCtx, controller)
			azapiv1pap.RegisterV1PAPServiceServer(grpcServer, papServer)
			return err
		})
	if err != nil {
		return nil, err
	}
	endpoints := []azservices.EndpointInitializer{endpoint}
	return endpoints, nil
}

// GetServiceConfigReader returns the service configuration reader.
func (f *PAPService) GetServiceConfigReader() (azruntime.ServiceConfigReader, error) {
	return f.configReader, nil
}
