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
	"testing"

	"github.com/stretchr/testify/assert"

	zapmodels "github.com/permguard/permguard/pkg/transport/models/zap"
)

// mockZAPStorage implements storage.ZAPCentralStorage for testing.
type mockZAPStorage struct {
	createZoneFn func(ctx context.Context, zone *zapmodels.Zone) (*zapmodels.Zone, error)
	updateZoneFn func(ctx context.Context, zone *zapmodels.Zone) (*zapmodels.Zone, error)
	deleteZoneFn func(ctx context.Context, zoneID int64) (*zapmodels.Zone, error)
	fetchZonesFn func(ctx context.Context, page int32, pageSize int32, fields map[string]any) ([]zapmodels.Zone, error)
}

func (m *mockZAPStorage) CreateZone(ctx context.Context, zone *zapmodels.Zone) (*zapmodels.Zone, error) {
	if m.createZoneFn != nil {
		return m.createZoneFn(ctx, zone)
	}
	return zone, nil
}

func (m *mockZAPStorage) UpdateZone(ctx context.Context, zone *zapmodels.Zone) (*zapmodels.Zone, error) {
	if m.updateZoneFn != nil {
		return m.updateZoneFn(ctx, zone)
	}
	return zone, nil
}

func (m *mockZAPStorage) DeleteZone(ctx context.Context, zoneID int64) (*zapmodels.Zone, error) {
	if m.deleteZoneFn != nil {
		return m.deleteZoneFn(ctx, zoneID)
	}
	return &zapmodels.Zone{ZoneID: zoneID}, nil
}

func (m *mockZAPStorage) FetchZones(ctx context.Context, page int32, pageSize int32, fields map[string]any) ([]zapmodels.Zone, error) {
	if m.fetchZonesFn != nil {
		return m.fetchZonesFn(ctx, page, pageSize, fields)
	}
	return []zapmodels.Zone{}, nil
}

func TestZAPController_CreateZone(t *testing.T) {
	tests := []struct {
		name    string
		input   *zapmodels.Zone
		wantErr bool
		errMsg  string
	}{
		{name: "valid zone", input: &zapmodels.Zone{Name: "test-zone"}, wantErr: false},
		{name: "nil zone", input: nil, wantErr: true, errMsg: "zap-controller: zone is nil"},
		{name: "empty name", input: &zapmodels.Zone{Name: ""}, wantErr: true, errMsg: "zap-controller: zone name is empty"},
		{name: "whitespace name", input: &zapmodels.Zone{Name: "   "}, wantErr: true, errMsg: "zap-controller: zone name is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl, _ := NewZAPController(nil, &mockZAPStorage{})
			result, err := ctrl.CreateZone(context.Background(), tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestZAPController_CreateZone_StorageError(t *testing.T) {
	mockStorage := &mockZAPStorage{
		createZoneFn: func(ctx context.Context, zone *zapmodels.Zone) (*zapmodels.Zone, error) {
			return nil, errors.New("db error")
		},
	}
	ctrl, _ := NewZAPController(nil, mockStorage)
	result, err := ctrl.CreateZone(context.Background(), &zapmodels.Zone{Name: "test"})
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "zap-controller:")
	assert.Contains(t, err.Error(), "db error")
}

func TestZAPController_UpdateZone(t *testing.T) {
	tests := []struct {
		name    string
		input   *zapmodels.Zone
		wantErr bool
		errMsg  string
	}{
		{name: "valid zone", input: &zapmodels.Zone{ZoneID: 1, Name: "updated"}, wantErr: false},
		{name: "nil zone", input: nil, wantErr: true, errMsg: "zap-controller: zone is nil"},
		{name: "zero zone id", input: &zapmodels.Zone{ZoneID: 0, Name: "test"}, wantErr: true, errMsg: "zap-controller: invalid zone id"},
		{name: "negative zone id", input: &zapmodels.Zone{ZoneID: -1, Name: "test"}, wantErr: true, errMsg: "zap-controller: invalid zone id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl, _ := NewZAPController(nil, &mockZAPStorage{})
			result, err := ctrl.UpdateZone(context.Background(), tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestZAPController_DeleteZone(t *testing.T) {
	tests := []struct {
		name    string
		zoneID  int64
		wantErr bool
		errMsg  string
	}{
		{name: "valid zone id", zoneID: 1, wantErr: false},
		{name: "zero zone id", zoneID: 0, wantErr: true, errMsg: "zap-controller: invalid zone id"},
		{name: "negative zone id", zoneID: -1, wantErr: true, errMsg: "zap-controller: invalid zone id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl, _ := NewZAPController(nil, &mockZAPStorage{})
			result, err := ctrl.DeleteZone(context.Background(), tt.zoneID)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestZAPController_FetchZones(t *testing.T) {
	ctrl, _ := NewZAPController(nil, &mockZAPStorage{})
	result, err := ctrl.FetchZones(context.Background(), 1, 10, map[string]any{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
}
