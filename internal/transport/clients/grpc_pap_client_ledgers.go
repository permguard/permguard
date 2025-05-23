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
	"context"
	"errors"
	"io"

	papv1 "github.com/permguard/permguard/internal/agents/services/pap/endpoints/api/v1"
	"github.com/permguard/permguard/pkg/transport/models/pap"
)

// CreateLedger creates a new ledger.
func (c *GrpcPAPClient) CreateLedger(zoneID int64, kind string, name string) (*pap.Ledger, error) {
	client, conn, err := c.createGRPCClient()
	defer conn.Close()
	if err != nil {
		return nil, err
	}
	ledger, err := client.CreateLedger(context.Background(), &papv1.LedgerCreateRequest{ZoneID: zoneID, Name: name, Kind: kind})
	if err != nil {
		return nil, err
	}
	return papv1.MapGrpcLedgerResponseToAgentLedger(ledger)
}

// UpdateLedger updates an ledger.
func (c *GrpcPAPClient) UpdateLedger(ledger *pap.Ledger) (*pap.Ledger, error) {
	if ledger == nil {
		return nil, errors.New("client: invalid ledger instance")
	}
	client, conn, err := c.createGRPCClient()
	defer conn.Close()
	if err != nil {
		return nil, err
	}
	updatedLedger, err := client.UpdateLedger(context.Background(), &papv1.LedgerUpdateRequest{
		LedgerID: ledger.LedgerID,
		ZoneID:   ledger.ZoneID,
		Kind:     ledger.Kind,
		Name:     ledger.Name,
	})
	if err != nil {
		return nil, err
	}
	return papv1.MapGrpcLedgerResponseToAgentLedger(updatedLedger)
}

// DeleteLedger deletes an ledger.
func (c *GrpcPAPClient) DeleteLedger(zoneID int64, ledgerID string) (*pap.Ledger, error) {
	client, conn, err := c.createGRPCClient()
	defer conn.Close()
	if err != nil {
		return nil, err
	}
	ledger, err := client.DeleteLedger(context.Background(), &papv1.LedgerDeleteRequest{ZoneID: zoneID, LedgerID: ledgerID})
	if err != nil {
		return nil, err
	}
	return papv1.MapGrpcLedgerResponseToAgentLedger(ledger)
}

// FetchLedgers returns all ledgers.
func (c *GrpcPAPClient) FetchLedgers(page int32, pageSize int32, zoneID int64) ([]pap.Ledger, error) {
	return c.FetchLedgersBy(page, pageSize, zoneID, "", "", "")
}

// FetchLedgersByID returns all ledgers filtering by ledger id.
func (c *GrpcPAPClient) FetchLedgersByID(page int32, pageSize int32, zoneID int64, ledgerID string) ([]pap.Ledger, error) {
	return c.FetchLedgersBy(page, pageSize, zoneID, ledgerID, "", "")
}

// FetchLedgersByName returns all ledgers filtering by name.
func (c *GrpcPAPClient) FetchLedgersByName(page int32, pageSize int32, zoneID int64, name string) ([]pap.Ledger, error) {
	return c.FetchLedgersBy(page, pageSize, zoneID, "", "", name)
}

// FetchLedgersBy returns all ledgers filtering by ledger id and name.
func (c *GrpcPAPClient) FetchLedgersBy(page int32, pageSize int32, zoneID int64, ledgerID string, kind string, name string) ([]pap.Ledger, error) {
	client, conn, err := c.createGRPCClient()
	defer conn.Close()
	if err != nil {
		return nil, err
	}
	ledgerFetchRequest := &papv1.LedgerFetchRequest{}
	ledgerFetchRequest.Page = &page
	ledgerFetchRequest.PageSize = &pageSize
	if zoneID > 0 {
		ledgerFetchRequest.ZoneID = zoneID
	}
	if kind != "" {
		ledgerFetchRequest.Kind = &kind
	}
	if name != "" {
		ledgerFetchRequest.Name = &name
	}
	if ledgerID != "" {
		ledgerFetchRequest.LedgerID = &ledgerID
	}
	stream, err := client.FetchLedgers(context.Background(), ledgerFetchRequest)
	if err != nil {
		return nil, err
	}
	ledgers := []pap.Ledger{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		ledger, err := papv1.MapGrpcLedgerResponseToAgentLedger(response)
		if err != nil {
			return nil, err
		}
		ledgers = append(ledgers, *ledger)
	}
	return ledgers, nil
}
