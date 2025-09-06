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

package controllers

import (
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	"github.com/permguard/permguard/pkg/transport/models/zap"
)

// ZAPController is the controller for the ZAP service.
type ZAPController struct {
	ctx     *services.ServiceContext
	storage storage.ZAPCentralStorage
}

// Setup initializes the service.
func (s ZAPController) Setup() error {
	return nil
}

// NewZAPController creates a new ZAP controller.
func NewZAPController(serviceContext *services.ServiceContext, zapCentralStorage storage.ZAPCentralStorage) (*ZAPController, error) {
	service := ZAPController{
		ctx:     serviceContext,
		storage: zapCentralStorage,
	}
	return &service, nil
}

// CreateZone creates a new zone.
func (s ZAPController) CreateZone(zone *zap.Zone) (*zap.Zone, error) {
	return s.storage.CreateZone(zone)
}

// UpdateZone updates a zone.
func (s ZAPController) UpdateZone(zone *zap.Zone) (*zap.Zone, error) {
	return s.storage.UpdateZone(zone)
}

// DeleteZone delete a zone.
func (s ZAPController) DeleteZone(zoneID int64) (*zap.Zone, error) {
	return s.storage.DeleteZone(zoneID)
}

// FetchZones returns all zones filtering by search criteria.
func (s ZAPController) FetchZones(page int32, pageSize int32, fields map[string]any) ([]zap.Zone, error) {
	return s.storage.FetchZones(page, pageSize, fields)
}
