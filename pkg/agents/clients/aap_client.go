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
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// GrpcAAPClient is the gRPC AAP client servicer.
type GrpcAAPClient interface {
	// CreateAccount creates a new account.
	CreateAccount(name string) (*azmodels.Account, error)
	// UpdateAccount updates an account.
	UpdateAccount(account *azmodels.Account) (*azmodels.Account, error)
	// DeleteAccount deletes an account.
	DeleteAccount(accountID int64) (*azmodels.Account, error)
	// FetchAccounts fetches accounts.
	FetchAccounts(page int32, pageSize int32) ([]azmodels.Account, error)
	// FetchAccountsByID fetches accounts by ID.
	FetchAccountsByID(page int32, pageSize int32, accountID int64) ([]azmodels.Account, error)
	// FetchAccountsByName fetches accounts by name.
	FetchAccountsByName(page int32, pageSize int32, name string) ([]azmodels.Account, error)
	// FetchAccountsBy fetches accounts by.
	FetchAccountsBy(page int32, pageSize int32, accountID int64, name string) ([]azmodels.Account, error)
}
