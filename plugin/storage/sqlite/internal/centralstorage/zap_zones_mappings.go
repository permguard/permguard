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

package centralstorage

import (
	"github.com/permguard/permguard/pkg/transport/models/zap"
	repos "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories"
)

// mapZoneToAgentZone maps a zone to a model Zone.
func mapZoneToAgentZone(zone *repos.Zone) (*zap.Zone, error) {
	return &zap.Zone{
		ZoneID:    zone.ZoneID,
		CreatedAt: zone.CreatedAt,
		UpdatedAt: zone.UpdatedAt,
		Name:      zone.Name,
	}, nil
}
