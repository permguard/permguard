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

package servers

import (
	"fmt"

	"github.com/permguard/permguard/common/pkg/extensions/copier"
	"github.com/permguard/permguard/internal/agents/services/pap"
	"github.com/permguard/permguard/internal/agents/services/pdp"
	"github.com/permguard/permguard/internal/agents/services/zap"
	"github.com/permguard/permguard/pkg/agents/servers"
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/plugin/storage/sqlite"
)

// CommunityServerInitializer is the community service factory initializer.
type CommunityServerInitializer struct {
	host      services.HostKind
	hostInfos map[services.HostKind]*services.HostInfo
	storages  []storage.StorageKind
	services  []services.ServiceKind
}

// NewCommunityServerInitializer creates a new community server initializer.
func NewCommunityServerInitializer(host services.HostKind) (servers.ServerInitializer, error) {
	template := `The official Permguard Server
Copyright © 2022 Nitro Agility S.r.l.

%s

  Find more information at: https://community.permguard.com/docs/0.0.x/devops/authz-server/configuration-options/`
	hostInfos := map[services.HostKind]*services.HostInfo{
		services.HostAllInOne: {Name: "AllInOne", Use: "all-in-one", Short: "The official Permguard Server - Start all services", Long: fmt.Sprintf(template, "Using this option all services are started.")},
		services.HostZAP:      {Name: "ZAP (Zone Administration Point)", Use: "pdp", Short: "The official Permguard Server - Start the ZAP service", Long: fmt.Sprintf(template, "Using this option the Zone Administration Point (ZAP) service is started.")},
		services.HostPAP:      {Name: "PAP (Policy Administration Point)", Use: "pap", Short: "The official Permguard Server - Start the PAP service", Long: fmt.Sprintf(template, "Using this option the Policy Administration Point (PAP) service is started.")},
		services.HostPIP:      {Name: "PIP (Policy Information Point)", Use: "pip", Short: "The official Permguard Server - Start the PIP service", Long: fmt.Sprintf(template, "Using this option the Policy Information Point (PIP) service is started.")},
		services.HostPDP:      {Name: "PDP (Policy Decision Point)", Use: "pdp", Short: "The official Permguard Server - Start the PDP service", Long: fmt.Sprintf(template, "Using this option the Policy Decision Point (PDP) service is started.")},
	}
	hosts := []services.HostKind{services.HostAllInOne, services.HostZAP, services.HostPAP, services.HostPIP, services.HostPDP}
	storages := []storage.StorageKind{storage.StorageSQLite}
	services := []services.ServiceKind{services.ServiceZAP, services.ServicePAP, services.ServicePIP, services.ServicePDP}

	if !host.IsValid(hosts) {
		panic(fmt.Sprintf("server: invalid server kind: %s", host))
	}
	return &CommunityServerInitializer{
		host:      host,
		hostInfos: hostInfos,
		storages:  storages,
		services:  host.Services(hosts, services),
	}, nil
}

// HasCentralStorage returns true if a central storage is required.
func (c *CommunityServerInitializer) HasCentralStorage() bool {
	return true
}

// Host returns the service kind set as host.
func (c *CommunityServerInitializer) Host() services.HostKind {
	return c.host
}

// HostInfo returns the infos of the service kind set as host.
func (c *CommunityServerInitializer) HostInfo() *services.HostInfo {
	return c.hostInfos[c.host]
}

// Storages returns the active storage kinds.
func (c *CommunityServerInitializer) Storages(centralStorageEngine storage.StorageKind) []storage.StorageKind {
	storages := []storage.StorageKind{}
	for _, storageKind := range c.storages {
		if storage.StorageNone.Equal(storageKind) {
			continue
		}
		if centralStorageEngine == storageKind {
			storages = append(storages, storageKind)
		}
	}
	return storages
}

// StoragesFactories returns the storage factories providers.
func (c *CommunityServerInitializer) StoragesFactories(centralStorageEngine storage.StorageKind) (map[storage.StorageKind]storage.StorageFactoryProvider, error) {
	factories := map[storage.StorageKind]storage.StorageFactoryProvider{}
	for _, storageKind := range c.Storages(centralStorageEngine) {
		switch storageKind {
		case storage.StorageSQLite:
			fFactCfg := func() (storage.StorageFactoryConfig, error) { return sqlite.NewSQLiteStorageFactoryConfig() }
			fFact := func(config storage.StorageFactoryConfig) (storage.StorageFactory, error) {
				return sqlite.NewSQLiteStorageFactory(config.(*sqlite.SQLiteStorageFactoryConfig))
			}
			fcty, err := storage.NewStorageFactoryProvider(fFactCfg, fFact)
			if err != nil {
				return nil, err
			}
			factories[storageKind] = *fcty
			continue
		}
	}
	return factories, nil
}

// Services returns the active service kinds.
func (c *CommunityServerInitializer) Services() []services.ServiceKind {
	return copier.CopySlice(c.services)
}

// ServicesFactories returns the service factories providers.
func (c *CommunityServerInitializer) ServicesFactories() (map[services.ServiceKind]services.ServiceFactoryProvider, error) {
	factories := map[services.ServiceKind]services.ServiceFactoryProvider{}
	for _, serviceKind := range c.services {
		switch serviceKind {
		case services.ServiceZAP:
			fFactCfg := func() (services.ServiceFactoryConfig, error) { return zap.NewZAPServiceFactoryConfig() }
			fFact := func(config services.ServiceFactoryConfig) (services.ServiceFactory, error) {
				return zap.NewZAPServiceFactory(config.(*zap.ZAPServiceFactoryConfig))
			}
			fcty, err := services.NewServiceFactoryProvider(fFactCfg, fFact)
			if err != nil {
				return nil, err
			}
			factories[serviceKind] = *fcty
			continue
		case services.ServicePAP:
			fFactCfg := func() (services.ServiceFactoryConfig, error) { return pap.NewPAPServiceFactoryConfig() }
			fFact := func(config services.ServiceFactoryConfig) (services.ServiceFactory, error) {
				return pap.NewPAPServiceFactory(config.(*pap.PAPServiceFactoryConfig))
			}
			fcty, err := services.NewServiceFactoryProvider(fFactCfg, fFact)
			if err != nil {
				return nil, err
			}
			factories[serviceKind] = *fcty
			continue
		case services.ServicePIP:
			continue
		case services.ServicePDP:
			fFactCfg := func() (services.ServiceFactoryConfig, error) { return pdp.NewPDPServiceFactoryConfig() }
			fFact := func(config services.ServiceFactoryConfig) (services.ServiceFactory, error) {
				return pdp.NewPDPServiceFactory(config.(*pdp.PDPServiceFactoryConfig))
			}
			fcty, err := services.NewServiceFactoryProvider(fFactCfg, fFact)
			if err != nil {
				return nil, err
			}
			factories[serviceKind] = *fcty
		}
	}
	return factories, nil
}
