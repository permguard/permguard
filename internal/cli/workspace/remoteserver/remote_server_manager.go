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
	"github.com/permguard/permguard/pkg/transport/grpctls"
	"github.com/permguard/permguard/pkg/transport/models/pap"
)

// hasTLSFlags returns true if any TLS-related client flag is set.
func hasTLSFlags(tlsCfg *grpctls.ClientConfig) bool {
	return tlsCfg != nil && (tlsCfg.SkipVerify || tlsCfg.CAFile != "" || tlsCfg.CertFile != "" || tlsCfg.Spiffe)
}

// grpcEndpoint builds a gRPC endpoint string using the remote's configured scheme.
// If the scheme is empty (backward compatibility), it falls back to auto-detect from TLS config.
// If the scheme conflicts with the TLS flags, it returns an error.
func grpcEndpoint(tlsCfg *grpctls.ClientConfig, remoteScheme string, host string, port int) (string, error) {
	tls := hasTLSFlags(tlsCfg)
	scheme := remoteScheme
	switch {
	case scheme == "":
		// Backward compatibility: auto-detect from TLS config.
		scheme = "grpc"
		if tls {
			scheme = "grpcs"
		}
	case scheme == "grpc" && tls:
		return "", errors.New("cli: remote scheme is 'grpc' (plaintext) but TLS flags are set — update the remote scheme to 'grpcs' with 'permguard remote add' or remove TLS flags")
	case scheme == "grpcs" && !tls:
		return "", errors.New("cli: remote scheme is 'grpcs' (TLS) but no TLS flags are set — add --tls-skip-verify or other TLS flags, or update the remote scheme to 'grpc'")
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port), nil
}

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
		return nil, errors.New("cli: remote info is nil — ensure a remote is configured with 'permguard workspace remote add'")
	}
	if ledgerInfo == nil {
		return nil, errors.New("cli: ledger info is nil — ensure a ledger is checked out with 'permguard checkout'")
	}
	tlsCfg := m.ctx.TLSClientConfig()
	zapEndpoint, err := grpcEndpoint(tlsCfg, remoteInfo.Scheme(), remoteInfo.Server(), remoteInfo.ZAPPort())
	if err != nil {
		return nil, err
	}
	zapClient, err := clients.NewGrpcZAPClient(zapEndpoint, tlsCfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = zapClient.Close() }()
	papEndpoint, err := grpcEndpoint(tlsCfg, remoteInfo.Scheme(), remoteInfo.Server(), remoteInfo.PAPPort())
	if err != nil {
		return nil, err
	}
	papClient, err := clients.NewGrpcPAPClient(papEndpoint, tlsCfg)
	if err != nil {
		return nil, err
	}
	defer func() { _ = papClient.Close() }()
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
func (m *Manager) NewPAPClientSession(server string, papPort int, scheme string) (*clients.GrpcPAPClientSession, error) {
	tlsCfg := m.ctx.TLSClientConfig()
	papEndpoint, err := grpcEndpoint(tlsCfg, scheme, server, papPort)
	if err != nil {
		return nil, err
	}
	papClient, err := clients.NewGrpcPAPClient(papEndpoint, tlsCfg)
	if err != nil {
		return nil, err
	}
	return papClient.Connect()
}
