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

	azcopier "github.com/permguard/permguard-core/pkg/extensions/copier"
	azipap "github.com/permguard/permguard/internal/agents/services/pap"
	azipdp "github.com/permguard/permguard/internal/agents/services/pdp"
	azizap "github.com/permguard/permguard/internal/agents/services/zap"
	azservers "github.com/permguard/permguard/pkg/agents/servers"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azisqlite "github.com/permguard/permguard/plugin/storage/sqlite"
)

// CommunityServerInitializer is the community service factory initializer.
type CommunityServerInitializer struct {
	host      azservices.HostKind
	hostInfos map[azservices.HostKind]*azservices.HostInfo
	storages  []azstorage.StorageKind
	services  []azservices.ServiceKind
}

// NewCommunityServerInitializer creates a new community server initializer.
func NewCommunityServerInitializer(host azservices.HostKind) (azservers.ServerInitializer, error) {
	template := `The official Permguard Server
Copyright © 2022 Nitro Agility S.r.l.

%s

  Find more information at: https://www.permguard.com/docs/0.0.x/devops/authz-server/configuration-options/`
	hostInfos := map[azservices.HostKind]*azservices.HostInfo{
		azservices.HostAllInOne: {Name: "AllInOne", Use: "all-in-one", Short: "The official Permguard Server - Start all services", Long: fmt.Sprintf(template, "Using this option all services are started.")},
		azservices.HostZAP:      {Name: "ZAP (Zone Administration Point)", Use: "pdp", Short: "The official Permguard Server - Start the ZAP service", Long: fmt.Sprintf(template, "Using this option the Zone Administration Point (ZAP) service is started.")},
		azservices.HostPAP:      {Name: "PAP (Policy Administration Point)", Use: "pap", Short: "The official Permguard Server - Start the PAP service", Long: fmt.Sprintf(template, "Using this option the Policy Administration Point (PAP) service is started.")},
		azservices.HostPIP:      {Name: "PIP (Policy Information Point)", Use: "pip", Short: "The official Permguard Server - Start the PIP service", Long: fmt.Sprintf(template, "Using this option the Policy Information Point (PIP) service is started.")},
		azservices.HostPDP:      {Name: "PDP (Policy Decision Point)", Use: "pdp", Short: "The official Permguard Server - Start the PDP service", Long: fmt.Sprintf(template, "Using this option the Policy Decision Point (PDP) service is started.")},
	}
	hosts := []azservices.HostKind{azservices.HostAllInOne, azservices.HostZAP, azservices.HostPAP, azservices.HostPIP, azservices.HostPDP}
	storages := []azstorage.StorageKind{azstorage.StorageSQLite}
	services := []azservices.ServiceKind{azservices.ServiceZAP, azservices.ServicePAP, azservices.ServicePIP, azservices.ServicePDP}

	if !host.IsValid(hosts) {
		panic(fmt.Sprintf("server: invalid server kind: %s", host))
	}
	return &CommunityServerInitializer{
		host:      host,
		hostInfos: hostInfos,
		storages:  storages,
		services:  host.GetServices(hosts, services),
	}, nil
}

// HasCentralStorage returns true if a central storage is required.
func (c *CommunityServerInitializer) HasCentralStorage() bool {
	return true
}

// GetHost returns the service kind set as host.
func (c *CommunityServerInitializer) GetHost() azservices.HostKind {
	return c.host
}

// GetHostInfo returns the infos of the service kind set as host.
func (c *CommunityServerInitializer) GetHostInfo() *azservices.HostInfo {
	return c.hostInfos[c.host]
}

// GetStorages returns the active storage kinds.
func (c *CommunityServerInitializer) GetStorages(centralStorageEngine azstorage.StorageKind) []azstorage.StorageKind {
	storages := []azstorage.StorageKind{}
	for _, storageKind := range c.storages {
		if azstorage.StorageNone.Equal(storageKind) {
			continue
		}
		if centralStorageEngine == storageKind {
			storages = append(storages, storageKind)
		}
	}
	return storages
}

// GetStoragesFactories returns the storage factories providers.
func (c *CommunityServerInitializer) GetStoragesFactories(centralStorageEngine azstorage.StorageKind) (map[azstorage.StorageKind]azstorage.StorageFactoryProvider, error) {
	factories := map[azstorage.StorageKind]azstorage.StorageFactoryProvider{}
	for _, storageKind := range c.GetStorages(centralStorageEngine) {
		switch storageKind {
		case azstorage.StorageSQLite:
			fFactCfg := func() (azstorage.StorageFactoryConfig, error) { return azisqlite.NewSQLiteStorageFactoryConfig() }
			fFact := func(config azstorage.StorageFactoryConfig) (azstorage.StorageFactory, error) {
				return azisqlite.NewSQLiteStorageFactory(config.(*azisqlite.SQLiteStorageFactoryConfig))
			}
			fcty, err := azstorage.NewStorageFactoryProvider(fFactCfg, fFact)
			if err != nil {
				return nil, err
			}
			factories[storageKind] = *fcty
			continue
		}
	}
	return factories, nil
}

// GetServices returns the active service kinds.
func (c *CommunityServerInitializer) GetServices() []azservices.ServiceKind {
	return azcopier.CopySlice(c.services)
}

// GetServicesFactories returns the service factories providers.
func (c *CommunityServerInitializer) GetServicesFactories() (map[azservices.ServiceKind]azservices.ServiceFactoryProvider, error) {
	factories := map[azservices.ServiceKind]azservices.ServiceFactoryProvider{}
	for _, serviceKind := range c.services {
		switch serviceKind {
		case azservices.ServiceZAP:
			fFactCfg := func() (azservices.ServiceFactoryConfig, error) { return azizap.NewZAPServiceFactoryConfig() }
			fFact := func(config azservices.ServiceFactoryConfig) (azservices.ServiceFactory, error) {
				return azizap.NewZAPServiceFactory(config.(*azizap.ZAPServiceFactoryConfig))
			}
			fcty, err := azservices.NewServiceFactoryProvider(fFactCfg, fFact)
			if err != nil {
				return nil, err
			}
			factories[serviceKind] = *fcty
			continue
		case azservices.ServicePAP:
			fFactCfg := func() (azservices.ServiceFactoryConfig, error) { return azipap.NewPAPServiceFactoryConfig() }
			fFact := func(config azservices.ServiceFactoryConfig) (azservices.ServiceFactory, error) {
				return azipap.NewPAPServiceFactory(config.(*azipap.PAPServiceFactoryConfig))
			}
			fcty, err := azservices.NewServiceFactoryProvider(fFactCfg, fFact)
			if err != nil {
				return nil, err
			}
			factories[serviceKind] = *fcty
			continue
		case azservices.ServicePIP:
			continue
		case azservices.ServicePDP:
			fFactCfg := func() (azservices.ServiceFactoryConfig, error) { return azipdp.NewPDPServiceFactoryConfig() }
			fFact := func(config azservices.ServiceFactoryConfig) (azservices.ServiceFactory, error) {
				return azipdp.NewPDPServiceFactory(config.(*azipdp.PDPServiceFactoryConfig))
			}
			fcty, err := azservices.NewServiceFactoryProvider(fFactCfg, fFact)
			if err != nil {
				return nil, err
			}
			factories[serviceKind] = *fcty
		}
	}
	return factories, nil
}
