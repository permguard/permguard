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

package e2e

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAccountsCreationAndDeletion tests the creation of a data sample.
func TestAccountsCreationAndDeletion(t *testing.T) {
	if !e2eEnabled() {
		t.Skip("skipping test; E2E env var not set correctly")
	}
	require := require.New(t)
	aapClient, err := newGrpcAAPClient()
	require.True(err == nil, "Error should be nil.")

	name := "dev-corporate"
	account, err := aapClient.CreateAccount(name)
	require.True(err == nil, "Error should be nil.")

	accounts, err := aapClient.GetAllAccounts()
	require.True(err == nil, "Error should be nil.")

	require.True(hasAccount(accounts, account), -1, "Account was not found.")

	checkAccount, err := aapClient.CreateAccount(name)
	require.True(err != nil, "Error should be not nil.")
	require.Nil(checkAccount, "Account should be nil.")

	deletedAccount, err := aapClient.DeleteAccount(account.AccountID)
	require.True(err == nil, "Error should be nil.")
	require.Equal(account.AccountID, deletedAccount.AccountID, "Account ID should be the same.")
}
