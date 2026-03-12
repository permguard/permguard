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
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	azpapctrl "github.com/permguard/permguard/internal/agents/services/pap/controllers"
	azpapv1 "github.com/permguard/permguard/internal/agents/services/pap/endpoints/api/v1"
	"github.com/permguard/permguard/pkg/agents/runtime"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
)

// Service holds the configuration for the server.
type Service struct {
	config       *ServiceConfig
	configReader runtime.ServiceConfigReader
}

// NewService creates a new server  configuration.
func NewService(papServiceCfg *ServiceConfig) (*Service, error) {
	configReader, err := services.NewServiceConfiguration(papServiceCfg.ConfigData())
	if err != nil {
		return nil, err
	}
	return &Service{
		config:       papServiceCfg,
		configReader: configReader,
	}, nil
}

// Service returns the service kind.
func (f *Service) Service() services.ServiceKind {
	return f.config.Service()
}

// Endpoints returns the service kind.
func (f *Service) Endpoints() ([]services.EndpointInitializer, error) {
	endpoint, err := services.NewEndpointInitializer(
		f.config.Service(),
		f.config.Port(),
		func(grpcServer *grpc.Server, srvCtx *services.ServiceContext, endptCtx *services.EndpointContext, storageConnector *storage.Connector) error {
			storageKind := f.config.StorageCentralEngine()
			centralStorage, err := storageConnector.CentralStorage(storageKind, endptCtx)
			if err != nil {
				return err
			}
			papCentralStorage, err := centralStorage.PAPCentralStorage()
			if err != nil {
				return err
			}
			controller, err := azpapctrl.NewPAPController(srvCtx, papCentralStorage)
			if err != nil {
				return nil
			}
			err = controller.Setup()
			if err != nil {
				return err
			}
			papServer, err := azpapv1.NewPAPServer(endptCtx, controller)
			azpapv1.RegisterV1PAPServiceServer(grpcServer, papServer)
			return err
		})
	if err != nil {
		return nil, err
	}
	endpoints := []services.EndpointInitializer{endpoint}
	return endpoints, nil
}

// Jobs returns the service background jobs.
func (f *Service) Jobs() ([]services.JobInitializer, error) {
	if !f.config.TxCleanupEnabled() {
		return nil, nil
	}
	interval := f.config.TxCleanupInterval()
	maxLifetime := f.config.TxMaxLifetime()
	job, err := services.NewJobInitializer(
		f.config.Service(),
		"tx-cleanup",
		func(ctx context.Context, srvCtx *services.ServiceContext, storageConnector *storage.Connector) error {
			logger := srvCtx.Logger()
			storageKind := f.config.StorageCentralEngine()
			centralStorage, err := storageConnector.CentralStorage(storageKind, srvCtx)
			if err != nil {
				return err
			}
			papStorage, err := centralStorage.PAPCentralStorage()
			if err != nil {
				return err
			}
			runCleanup := func() {
				cleaned, deleted, err := papStorage.CleanupStaleTransactions(ctx, maxLifetime)
				if err != nil {
					logger.Error("Transaction cleanup failed", zap.Error(err))
					return
				}
				if cleaned > 0 {
					logger.Info(fmt.Sprintf("Transaction cleanup: cleaned %d stale session(s), deleted %d object(s)", cleaned, deleted))
				}
			}
			// Run immediately on startup.
			runCleanup()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-ticker.C:
					runCleanup()
				}
			}
		},
	)
	if err != nil {
		return nil, err
	}
	return []services.JobInitializer{job}, nil
}

// ServiceConfigReader returns the service configuration reader.
func (f *Service) ServiceConfigReader() (runtime.ServiceConfigReader, error) {
	return f.configReader, nil
}
