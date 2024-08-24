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

	azruntime "github.com/permguard/permguard/pkg/agents/runtime"
	azctrlpdp "github.com/permguard/permguard/internal/agents/services/pdp/controllers"
	azapiv1pdp "github.com/permguard/permguard/internal/agents/services/pdp/endpoints/api/v1"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// PDPService holds the configuration for the server.
type PDPService struct {
	config 			*PDPServiceConfig
	configReader	azruntime.ServiceConfigReader
}

// NewPDPService creates a new server  configuration.
func NewPDPService(pdpServiceCfg *PDPServiceConfig) (*PDPService, error) {
	configReader, err := azservices.NewServiceConfiguration(pdpServiceCfg.GetConfigData())
	if err != nil {
		return nil, err
	}
	return &PDPService{
		config: pdpServiceCfg,
		configReader: configReader,
	}, nil
}

// GetService returns the service kind.
func (f *PDPService) GetService() azservices.ServiceKind {
	return f.config.GetService()
}

// GetEndpoints returns the service kind.
func (f *PDPService) GetEndpoints() ([]azservices.EndpointInitializer, error) {
	endpoint, err := azservices.NewEndpointInitializer(
		f.config.GetService(),
		f.config.GetPort(),
		func(grpcServer *grpc.Server, srvCtx *azservices.ServiceContext, endptCtx *azservices.EndpointContext, storageConnector *azstorage.StorageConnector) error {
			controller, err := azctrlpdp.NewPDPLocalController(srvCtx)
			if err != nil {
				return nil
			}
			// TODO: Implement Setup
			//err = controller.Setup()
			// if err != nil {
			// 	return err
			// }
			pdpServer, err := azapiv1pdp.NewV1PDPServer(endptCtx, controller)
			azapiv1pdp.RegisterV1PDPServiceServer(grpcServer, pdpServer)
			return err
		})
	if err != nil {
		return nil, err
	}
	endpoints := []azservices.EndpointInitializer{endpoint}
	return endpoints, nil
}

// GetServiceConfigReader returns the service configuration reader.
func (f *PDPService) GetServiceConfigReader() (azruntime.ServiceConfigReader, error) {
	return f.configReader, nil
}
