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

package grpcclients

import (
	"context"
	"errors"

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
		return nil, errors.New("client: invalid account instance")
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

// GetAllAccounts returns all the accounts.
func (c *GrpcAAPClient) GetAllAccounts() ([]azmodels.Account, error) {
	return c.GetAccountsBy(0, "")
}

// GetAccountsByID returns all accounts filtering by account id.
func (c *GrpcAAPClient) GetAccountsByID(accountID int64) ([]azmodels.Account, error) {
	return c.GetAccountsBy(accountID, "")
}

// GetAccountsByName returns all accounts filtering by name.
func (c *GrpcAAPClient) GetAccountsByName(name string) ([]azmodels.Account, error) {
	return c.GetAccountsBy(0, name)
}

// GetAccountsBy returns all accounts filtering by account id and name.
func (c *GrpcAAPClient) GetAccountsBy(accountID int64, name string) ([]azmodels.Account, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	accountGetRequest := &azapiv1aap.AccountGetRequest{}
	if accountID > 0 {
		accountGetRequest.AccountID = &accountID
	}
	if name != "" {
		accountGetRequest.Name = &name
	}
	accountList, err := client.GetAllAccounts(context.Background(), accountGetRequest)
	if err != nil {
		return nil, err
	}
	accounts := make([]azmodels.Account, len(accountList.Accounts))
	for i, account := range accountList.Accounts {
		account, err := azapiv1aap.MapGrpcAccountResponseToAgentAccount(account)
		if err != nil {
			return nil, err
		}
		accounts[i] = *account
	}
	return accounts, nil
}
