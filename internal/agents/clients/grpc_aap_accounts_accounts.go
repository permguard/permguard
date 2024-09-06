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

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azapiv1aap "github.com/permguard/permguard/internal/agents/services/aap/endpoints/api/v1"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// CreateAccount creates a new account.
func (c *GrpcAAPClient) CreateAccount(name string) (*azmodels.Account, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	account, err := client.CreateAccount(context.Background(), &azapiv1aap.AccountCreateRequest{Name: name})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcAccountResponseToAgentAccount(account)
}

// UpdateAccount updates an account.
func (c *GrpcAAPClient) UpdateAccount(account *azmodels.Account) (*azmodels.Account, error) {
	if account == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientGeneric, "client: invalid account instance.")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedAccount, err := client.UpdateAccount(context.Background(), &azapiv1aap.AccountUpdateRequest{
		AccountID: account.AccountID,
		Name:      account.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcAccountResponseToAgentAccount(updatedAccount)
}

// DeleteAccount deletes an account.
func (c *GrpcAAPClient) DeleteAccount(accountID int64) (*azmodels.Account, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	account, err := client.DeleteAccount(context.Background(), &azapiv1aap.AccountDeleteRequest{AccountID: accountID})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcAccountResponseToAgentAccount(account)
}

// FetchAccounts returns all accounts.
func (c *GrpcAAPClient) FetchAccounts(page int32, pageSize int32) ([]azmodels.Account, error) {
	return c.FetchAccountsBy(page, pageSize, 0, "")
}

// FetchAccountsByID returns all accounts filtering by account id.
func (c *GrpcAAPClient) FetchAccountsByID(page int32, pageSize int32, accountID int64) ([]azmodels.Account, error) {
	return c.FetchAccountsBy(page, pageSize, accountID, "")
}

// FetchAccountsByName returns all accounts filtering by name.
func (c *GrpcAAPClient) FetchAccountsByName(page int32, pageSize int32, name string) ([]azmodels.Account, error) {
	return c.FetchAccountsBy(page, pageSize, 0, name)
}

// FetchAccountsBy returns all accounts filtering by account id and name.
func (c *GrpcAAPClient) FetchAccountsBy(page int32, pageSize int32, accountID int64, name string) ([]azmodels.Account, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	accountFetchRequest := &azapiv1aap.AccountFetchRequest{}
	accountFetchRequest.Page = &page
	accountFetchRequest.PageSize = &pageSize
	if accountID > 0 {
		accountFetchRequest.AccountID = &accountID
	}
	if name != "" {
		accountFetchRequest.Name = &name
	}
	stream, err := client.FetchAccounts(context.Background(), accountFetchRequest)
	if err != nil {
		return nil, err
	}
	accounts := []azmodels.Account{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		account, err := azapiv1aap.MapGrpcAccountResponseToAgentAccount(response)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, *account)
	}
	return accounts, nil
}
