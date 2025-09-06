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

package v1

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/permguard/permguard/pkg/transport/models/zap"
)

// MapPointerStringToString maps a pointer string to a string.
func MapPointerStringToString(str *string) string {
	response := ""
	if str != nil {
		response = *str
	}
	return response
}

// MapGrpcZoneResponseToAgentZone maps the gRPC zone to the agent zone.
func MapGrpcZoneResponseToAgentZone(zone *ZoneResponse) (*zap.Zone, error) {
	return &zap.Zone{
		ZoneID:    zone.ZoneID,
		CreatedAt: zone.CreatedAt.AsTime(),
		UpdatedAt: zone.UpdatedAt.AsTime(),
		Name:      zone.Name,
	}, nil
}

// MapAgentZoneToGrpcZoneResponse maps the agent zone to the gRPC zone.
func MapAgentZoneToGrpcZoneResponse(zone *zap.Zone) (*ZoneResponse, error) {
	return &ZoneResponse{
		ZoneID:    zone.ZoneID,
		CreatedAt: timestamppb.New(zone.CreatedAt),
		UpdatedAt: timestamppb.New(zone.UpdatedAt),
		Name:      zone.Name,
	}, nil
}
