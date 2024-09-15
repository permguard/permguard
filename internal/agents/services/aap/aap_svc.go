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

package aap

import (
	"google.golang.org/grpc"

	azctrlaap "github.com/permguard/permguard/internal/agents/services/aap/controllers"
	azapiv1aap "github.com/permguard/permguard/internal/agents/services/aap/endpoints/api/v1"
	azruntime "github.com/permguard/permguard/pkg/agents/runtime"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// AAPService holds the configuration for the server.
type AAPService struct {
	config       *AAPServiceConfig
	configReader azruntime.ServiceConfigReader
}

// NewAAPService creates a new server  configuration.
func NewAAPService(aapServiceCfg *AAPServiceConfig) (*AAPService, error) {
	configReader, err := azservices.NewServiceConfiguration(aapServiceCfg.GetConfigData())
	if err != nil {
		return nil, err
	}
	return &AAPService{
		config:       aapServiceCfg,
		configReader: configReader,
	}, nil
}

// GetService returns the service kind.
func (f *AAPService) GetService() azservices.ServiceKind {
	return f.config.GetService()
}

// GetEndpoints returns the service kind.
func (f *AAPService) GetEndpoints() ([]azservices.EndpointInitializer, error) {
	endpoint, err := azservices.NewEndpointInitializer(
		f.config.GetService(),
		f.config.GetPort(),
		func(grpcServer *grpc.Server, srvCtx *azservices.ServiceContext, endptCtx *azservices.EndpointContext, storageConnector *azstorage.StorageConnector) error {
			centralStorage, err := storageConnector.GetCentralStorage(endptCtx)
			if err != nil {
				return err
			}
			aapCentralStorage, err := centralStorage.GetAAPCentralStorage()
			if err != nil {
				return err
			}
			controller, err := azctrlaap.NewAAPController(srvCtx, aapCentralStorage)
			if err != nil {
				return nil
			}
			err = controller.Setup()
			if err != nil {
				return err
			}
			aapServer, err := azapiv1aap.NewV1AAPServer(endptCtx, controller)
			azapiv1aap.RegisterV1AAPServiceServer(grpcServer, aapServer)
			return err
		})
	if err != nil {
		return nil, err
	}
	endpoints := []azservices.EndpointInitializer{endpoint}
	return endpoints, nil
}

// GetServiceConfigReader returns the service configuration reader.
func (f *AAPService) GetServiceConfigReader() (azruntime.ServiceConfigReader, error) {
	return f.configReader, nil
}
