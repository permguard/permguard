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
	"errors"
	"fmt"
	"strings"

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
	hostInfo *services.HostInfo
	storages []storage.Kind
	services []services.ServiceKind
}

// NewCommunityServerInitializer creates a new community server initializer.
func NewCommunityServerInitializer(displayName string, serviceKinds []services.ServiceKind) (servers.ServerInitializer, error) {
	if len(serviceKinds) == 0 {
		return nil, errors.New("server: at least one service kind must be specified")
	}
	svcNames := make([]string, len(serviceKinds))
	for i, svc := range serviceKinds {
		svcNames[i] = svc.String()
	}
	template := `The official Permguard Server
Copyright © 2022 Nitro Agility S.r.l.

%s

  Find more information at: https://community.permguard.com/docs/0.0.x/devops/authz-server/configuration-options/`
	hostInfo := &services.HostInfo{
		Name:  displayName,
		Use:   strings.ToLower(strings.ReplaceAll(displayName, " ", "-")),
		Short: fmt.Sprintf("The official Permguard Server - %s", displayName),
		Long:  fmt.Sprintf(template, fmt.Sprintf("Starting services: %s.", strings.Join(svcNames, ", "))),
	}
	storages := []storage.Kind{storage.StorageSQLite}
	return &CommunityServerInitializer{
		hostInfo: hostInfo,
		storages: storages,
		services: copier.CopySlice(serviceKinds),
	}, nil
}

// HasCentralStorage returns true if a central storage is required.
func (c *CommunityServerInitializer) HasCentralStorage() bool {
	return true
}

// HostInfo returns the infos of the service kind set as host.
func (c *CommunityServerInitializer) HostInfo() *services.HostInfo {
	return c.hostInfo
}

// Storages returns the active storage kinds.
func (c *CommunityServerInitializer) Storages(centralStorageEngine storage.Kind) []storage.Kind {
	storages := []storage.Kind{}
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
func (c *CommunityServerInitializer) StoragesFactories(centralStorageEngine storage.Kind) (map[storage.Kind]storage.FactoryProvider, error) {
	factories := map[storage.Kind]storage.FactoryProvider{}
	for _, storageKind := range c.Storages(centralStorageEngine) {
		if storageKind == storage.StorageSQLite {
			fFactCfg := func() (storage.FactoryConfig, error) { return sqlite.NewStorageFactoryConfig() }
			fFact := func(config storage.FactoryConfig) (storage.Factory, error) {
				return sqlite.NewStorageFactory(config.(*sqlite.StorageFactoryConfig))
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
			fFactCfg := func() (services.ServiceFactoryConfig, error) { return zap.NewServiceFactoryConfig() }
			fFact := func(config services.ServiceFactoryConfig) (services.ServiceFactory, error) {
				return zap.NewServiceFactory(config.(*zap.ServiceFactoryConfig))
			}
			fcty, err := services.NewServiceFactoryProvider(fFactCfg, fFact)
			if err != nil {
				return nil, err
			}
			factories[serviceKind] = *fcty
			continue
		case services.ServicePAP:
			fFactCfg := func() (services.ServiceFactoryConfig, error) { return pap.NewServiceFactoryConfig() }
			fFact := func(config services.ServiceFactoryConfig) (services.ServiceFactory, error) {
				return pap.NewServiceFactory(config.(*pap.ServiceFactoryConfig))
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
			fFactCfg := func() (services.ServiceFactoryConfig, error) { return pdp.NewServiceFactoryConfig() }
			fFact := func(config services.ServiceFactoryConfig) (services.ServiceFactory, error) {
				return pdp.NewServiceFactory(config.(*pdp.ServiceFactoryConfig))
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
