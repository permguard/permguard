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

	notppkts "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	statemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	smpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
	"github.com/permguard/permguard/pkg/transport/models/pap"
)

// mockPAPStorage implements storage.PAPCentralStorage for testing.
type mockPAPStorage struct {
	createLedgerFn func(ctx context.Context, ledger *pap.Ledger) (*pap.Ledger, error)
	updateLedgerFn func(ctx context.Context, ledger *pap.Ledger) (*pap.Ledger, error)
	deleteLedgerFn func(ctx context.Context, zoneID int64, ledgerID string) (*pap.Ledger, error)
	fetchLedgersFn func(ctx context.Context, page int32, pageSize int32, zoneID int64, fields map[string]any) ([]pap.Ledger, error)
}

func (m *mockPAPStorage) CreateLedger(ctx context.Context, ledger *pap.Ledger) (*pap.Ledger, error) {
	if m.createLedgerFn != nil {
		return m.createLedgerFn(ctx, ledger)
	}
	return ledger, nil
}
func (m *mockPAPStorage) UpdateLedger(ctx context.Context, ledger *pap.Ledger) (*pap.Ledger, error) {
	if m.updateLedgerFn != nil {
		return m.updateLedgerFn(ctx, ledger)
	}
	return ledger, nil
}
func (m *mockPAPStorage) DeleteLedger(ctx context.Context, zoneID int64, ledgerID string) (*pap.Ledger, error) {
	if m.deleteLedgerFn != nil {
		return m.deleteLedgerFn(ctx, zoneID, ledgerID)
	}
	return &pap.Ledger{ZoneID: zoneID, LedgerID: ledgerID}, nil
}
func (m *mockPAPStorage) FetchLedgers(ctx context.Context, page int32, pageSize int32, zoneID int64, fields map[string]any) ([]pap.Ledger, error) {
	if m.fetchLedgersFn != nil {
		return m.fetchLedgersFn(ctx, page, pageSize, zoneID, fields)
	}
	return []pap.Ledger{}, nil
}

// NOTP stubs (not tested in this file)
func (m *mockPAPStorage) OnPullHandleRequestCurrentState(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}
func (m *mockPAPStorage) OnPullSendNotifyCurrentStateResponse(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}
func (m *mockPAPStorage) OnPullSendNegotiationRequest(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}
func (m *mockPAPStorage) OnPullHandleNegotiationResponse(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}
func (m *mockPAPStorage) OnPullHandleExchangeDataStream(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}
func (m *mockPAPStorage) OnPullHandleCommit(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}
func (m *mockPAPStorage) OnPushHandleNotifyCurrentState(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}
func (m *mockPAPStorage) OnPushSendNotifyCurrentStateResponse(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}
func (m *mockPAPStorage) OnPushSendNegotiationRequest(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}
func (m *mockPAPStorage) OnPushHandleNegotiationResponse(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}
func (m *mockPAPStorage) OnPushHandleExchangeDataStream(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}
func (m *mockPAPStorage) OnPushSendCommit(_ *statemachines.HandlerContext, _ *smpackets.StatePacket, _ []notppkts.Packetable) (*statemachines.HostHandlerReturn, error) {
	return nil, nil
}

func TestPAPController_CreateLedger(t *testing.T) {
	tests := []struct {
		name    string
		input   *pap.Ledger
		wantErr bool
		errMsg  string
	}{
		{name: "valid ledger", input: &pap.Ledger{ZoneID: 1, Name: "test-ledger"}, wantErr: false},
		{name: "nil ledger", input: nil, wantErr: true, errMsg: "pap-controller: ledger is nil"},
		{name: "zero zone id", input: &pap.Ledger{ZoneID: 0, Name: "test"}, wantErr: true, errMsg: "pap-controller: invalid zone id"},
		{name: "empty name", input: &pap.Ledger{ZoneID: 1, Name: ""}, wantErr: true, errMsg: "pap-controller: ledger name is empty"},
		{name: "whitespace name", input: &pap.Ledger{ZoneID: 1, Name: "   "}, wantErr: true, errMsg: "pap-controller: ledger name is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl, _ := NewPAPController(nil, &mockPAPStorage{})
			result, err := ctrl.CreateLedger(context.Background(), tt.input)
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

func TestPAPController_CreateLedger_StorageError(t *testing.T) {
	mockStorage := &mockPAPStorage{
		createLedgerFn: func(ctx context.Context, ledger *pap.Ledger) (*pap.Ledger, error) {
			return nil, errors.New("db error")
		},
	}
	ctrl, _ := NewPAPController(nil, mockStorage)
	result, err := ctrl.CreateLedger(context.Background(), &pap.Ledger{ZoneID: 1, Name: "test"})
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "pap-controller:")
	assert.Contains(t, err.Error(), "db error")
}

func TestPAPController_UpdateLedger(t *testing.T) {
	tests := []struct {
		name    string
		input   *pap.Ledger
		wantErr bool
		errMsg  string
	}{
		{name: "valid ledger", input: &pap.Ledger{ZoneID: 1, LedgerID: "abc", Name: "updated"}, wantErr: false},
		{name: "nil ledger", input: nil, wantErr: true, errMsg: "pap-controller: ledger is nil"},
		{name: "zero zone id", input: &pap.Ledger{ZoneID: 0, LedgerID: "abc"}, wantErr: true, errMsg: "pap-controller: invalid zone id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl, _ := NewPAPController(nil, &mockPAPStorage{})
			result, err := ctrl.UpdateLedger(context.Background(), tt.input)
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

func TestPAPController_DeleteLedger(t *testing.T) {
	tests := []struct {
		name     string
		zoneID   int64
		ledgerID string
		wantErr  bool
		errMsg   string
	}{
		{name: "valid delete", zoneID: 1, ledgerID: "abc", wantErr: false},
		{name: "zero zone id", zoneID: 0, ledgerID: "abc", wantErr: true, errMsg: "pap-controller: invalid zone id"},
		{name: "empty ledger id", zoneID: 1, ledgerID: "", wantErr: true, errMsg: "pap-controller: ledger id is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl, _ := NewPAPController(nil, &mockPAPStorage{})
			result, err := ctrl.DeleteLedger(context.Background(), tt.zoneID, tt.ledgerID)
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

func TestPAPController_FetchLedgers(t *testing.T) {
	ctrl, _ := NewPAPController(nil, &mockPAPStorage{})
	result, err := ctrl.FetchLedgers(context.Background(), 1, 10, 1, map[string]any{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
}
