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
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
	zapmodels "github.com/permguard/permguard/pkg/transport/models/zap"
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
func (s ZAPController) CreateZone(ctx context.Context, zone *zapmodels.Zone) (*zapmodels.Zone, error) {
	var logger *zap.Logger
	if s.ctx != nil {
		logger = s.ctx.Logger()
	}

	if zone == nil {
		return nil, errors.New("zap-controller: zone is nil")
	}
	if strings.TrimSpace(zone.Name) == "" {
		return nil, errors.New("zap-controller: zone name is empty")
	}

	if logger != nil {
		logger.Info("creating zone", zap.String("name", zone.Name))
	}

	result, err := s.storage.CreateZone(ctx, zone)
	if err != nil {
		if logger != nil {
			logger.Error("failed to create zone", zap.Error(err))
		}
		return nil, fmt.Errorf("zap-controller: %w", err)
	}

	return result, nil
}

// UpdateZone updates a zone.
func (s ZAPController) UpdateZone(ctx context.Context, zone *zapmodels.Zone) (*zapmodels.Zone, error) {
	var logger *zap.Logger
	if s.ctx != nil {
		logger = s.ctx.Logger()
	}

	if zone == nil {
		return nil, errors.New("zap-controller: zone is nil")
	}
	if zone.ZoneID <= 0 {
		return nil, fmt.Errorf("zap-controller: invalid zone id %d", zone.ZoneID)
	}

	if logger != nil {
		logger.Info("updating zone", zap.Int64("zone_id", zone.ZoneID), zap.String("name", zone.Name))
	}

	result, err := s.storage.UpdateZone(ctx, zone)
	if err != nil {
		if logger != nil {
			logger.Error("failed to update zone", zap.Int64("zone_id", zone.ZoneID), zap.Error(err))
		}
		return nil, fmt.Errorf("zap-controller: %w", err)
	}

	return result, nil
}

// DeleteZone delete a zone.
func (s ZAPController) DeleteZone(ctx context.Context, zoneID int64) (*zapmodels.Zone, error) {
	var logger *zap.Logger
	if s.ctx != nil {
		logger = s.ctx.Logger()
	}

	if zoneID <= 0 {
		return nil, fmt.Errorf("zap-controller: invalid zone id %d", zoneID)
	}

	if logger != nil {
		logger.Info("deleting zone", zap.Int64("zone_id", zoneID))
	}

	result, err := s.storage.DeleteZone(ctx, zoneID)
	if err != nil {
		if logger != nil {
			logger.Error("failed to delete zone", zap.Int64("zone_id", zoneID), zap.Error(err))
		}
		return nil, fmt.Errorf("zap-controller: %w", err)
	}

	return result, nil
}

// FetchZones returns all zones filtering by search criteria.
func (s ZAPController) FetchZones(ctx context.Context, page int32, pageSize int32, fields map[string]any) ([]zapmodels.Zone, error) {
	var logger *zap.Logger
	if s.ctx != nil {
		logger = s.ctx.Logger()
	}

	if logger != nil {
		logger.Info("fetching zones", zap.Int32("page", page), zap.Int32("page_size", pageSize))
	}

	result, err := s.storage.FetchZones(ctx, page, pageSize, fields)
	if err != nil {
		if logger != nil {
			logger.Error("failed to fetch zones", zap.Error(err))
		}
		return nil, fmt.Errorf("zap-controller: %w", err)
	}

	return result, nil
}
