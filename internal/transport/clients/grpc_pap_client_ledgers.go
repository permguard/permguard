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
	"io"

	azapiv1pap "github.com/permguard/permguard/internal/agents/services/pap/endpoints/api/v1"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelpap "github.com/permguard/permguard/pkg/transport/models/pap"
)

// CreateLedger creates a new ledger.
func (c *GrpcPAPClient) CreateLedger(applicationID int64, kind string, name string) (*azmodelpap.Ledger, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	ledger, err := client.CreateLedger(context.Background(), &azapiv1pap.LedgerCreateRequest{ApplicationID: applicationID, Name: name, Kind: kind})
	if err != nil {
		return nil, err
	}
	return azapiv1pap.MapGrpcLedgerResponseToAgentLedger(ledger)
}

// UpdateLedger updates an ledger.
func (c *GrpcPAPClient) UpdateLedger(ledger *azmodelpap.Ledger) (*azmodelpap.Ledger, error) {
	if ledger == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientGeneric, "client: invalid ledger instance")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedLedger, err := client.UpdateLedger(context.Background(), &azapiv1pap.LedgerUpdateRequest{
		LedgerID:      ledger.LedgerID,
		ApplicationID: ledger.ApplicationID,
		Kind:          ledger.Kind,
		Name:          ledger.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1pap.MapGrpcLedgerResponseToAgentLedger(updatedLedger)
}

// DeleteLedger deletes an ledger.
func (c *GrpcPAPClient) DeleteLedger(applicationID int64, ledgerID string) (*azmodelpap.Ledger, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	ledger, err := client.DeleteLedger(context.Background(), &azapiv1pap.LedgerDeleteRequest{ApplicationID: applicationID, LedgerID: ledgerID})
	if err != nil {
		return nil, err
	}
	return azapiv1pap.MapGrpcLedgerResponseToAgentLedger(ledger)
}

// FetchLedgers returns all ledgers.
func (c *GrpcPAPClient) FetchLedgers(page int32, pageSize int32, applicationID int64) ([]azmodelpap.Ledger, error) {
	return c.FetchLedgersBy(page, pageSize, applicationID, "", "", "")
}

// FetchLedgersByID returns all ledgers filtering by ledger id.
func (c *GrpcPAPClient) FetchLedgersByID(page int32, pageSize int32, applicationID int64, ledgerID string) ([]azmodelpap.Ledger, error) {
	return c.FetchLedgersBy(page, pageSize, applicationID, ledgerID, "", "")
}

// FetchLedgersByName returns all ledgers filtering by name.
func (c *GrpcPAPClient) FetchLedgersByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodelpap.Ledger, error) {
	return c.FetchLedgersBy(page, pageSize, applicationID, "", "", name)
}

// FetchLedgersBy returns all ledgers filtering by ledger id and name.
func (c *GrpcPAPClient) FetchLedgersBy(page int32, pageSize int32, applicationID int64, ledgerID string, kind string, name string) ([]azmodelpap.Ledger, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	ledgerFetchRequest := &azapiv1pap.LedgerFetchRequest{}
	ledgerFetchRequest.Page = &page
	ledgerFetchRequest.PageSize = &pageSize
	if applicationID > 0 {
		ledgerFetchRequest.ApplicationID = applicationID
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
	ledgers := []azmodelpap.Ledger{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		ledger, err := azapiv1pap.MapGrpcLedgerResponseToAgentLedger(response)
		if err != nil {
			return nil, err
		}
		ledgers = append(ledgers, *ledger)
	}
	return ledgers, nil
}
