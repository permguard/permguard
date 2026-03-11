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

package remoteserver

import (
	"errors"
	"fmt"

	"github.com/permguard/permguard/internal/cli/common"
	azwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/internal/transport/clients"
	"github.com/permguard/permguard/pkg/transport/models/pap"
)

// Manager implements the internal manager for the remote file.
type Manager struct {
	ctx *common.CliCommandContext
}

// NewManager creates a new remoteuration manager.
func NewManager(ctx *common.CliCommandContext) (*Manager, error) {
	return &Manager{
		ctx: ctx,
	}, nil
}

// ServerRemoteLedger gets the remote ledger from the server.
func (m *Manager) ServerRemoteLedger(remoteInfo *azwkscommon.RemoteInfo, ledgerInfo *azwkscommon.LedgerInfo) (*pap.Ledger, error) {
	if remoteInfo == nil {
		return nil, errors.New("cli: remote info is nil")
	}
	if ledgerInfo == nil {
		return nil, errors.New("cli: ledger info is nil")
	}
	zoneerver := fmt.Sprintf("grpc://%s:%d", remoteInfo.Server(), remoteInfo.ZAPPort())
	zapClient, err := clients.NewGrpcZAPClient(zoneerver)
	if err != nil {
		return nil, err
	}
	pppServer := fmt.Sprintf("grpc://%s:%d", remoteInfo.Server(), remoteInfo.PAPPort())
	papClient, err := clients.NewGrpcPAPClient(pppServer)
	if err != nil {
		return nil, err
	}
	zoneID := ledgerInfo.ZoneID()
	ledger := ledgerInfo.Ledger()
	srvZones, err := zapClient.FetchZonesByID(1, 1, zoneID)
	if err != nil || srvZones == nil || len(srvZones) == 0 {
		return nil, errors.Join(fmt.Errorf("cli: zone %d does not exist", zoneID), err)
	}
	srvLedger, err := papClient.FetchLedgersByName(1, 1, zoneID, ledger)
	if err != nil || srvLedger == nil || len(srvLedger) == 0 {
		return nil, errors.Join(fmt.Errorf("cli: ledger %s does not exist", ledger), err)
	}
	if srvLedger[0].Name != ledger {
		return nil, fmt.Errorf("cli: ledger %s not found", ledger)
	}
	return &srvLedger[0], nil
}

// NewPAPClientSession creates a new gRPC PAP client session with a reusable connection.
func (m *Manager) NewPAPClientSession(server string, papPort int) (*clients.GrpcPAPClientSession, error) {
	pppServer := fmt.Sprintf("grpc://%s:%d", server, papPort)
	papClient, err := clients.NewGrpcPAPClient(pppServer)
	if err != nil {
		return nil, err
	}
	return papClient.Connect()
}
