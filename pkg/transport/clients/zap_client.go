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

package clients

import (
	"github.com/permguard/permguard/pkg/transport/models/zap"
)

// GrpcZAPClient is the gRPC ZAP client servicer.
type GrpcZAPClient interface {
	// CreateZone creates a new zone.
	CreateZone(name string) (*zap.Zone, error)
	// UpdateZone updates a zone.
	UpdateZone(zone *zap.Zone) (*zap.Zone, error)
	// DeleteZone deletes a zone.
	DeleteZone(zoneID int64) (*zap.Zone, error)
	// FetchZones fetches zones.
	FetchZones(page int32, pageSize int32) ([]zap.Zone, error)
	// FetchZonesByID fetches zones by ID.
	FetchZonesByID(page int32, pageSize int32, zoneID int64) ([]zap.Zone, error)
	// FetchZonesByName fetches zones by name.
	FetchZonesByName(page int32, pageSize int32, name string) ([]zap.Zone, error)
	// FetchZonesBy fetches zones by.
	FetchZonesBy(page int32, pageSize int32, zoneID int64, name string) ([]zap.Zone, error)
}
