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

type seedData struct {
	accountName     string
	identitySources map[string]map[string][]string
	tenants         []string
	repositories    map[string]string
}

// createSeedData creates a new account.
func createSeedData(require *require.Assertions, sData *seedData) {
	aapClient, err := newGrpcAAPClient()
	require.True(err == nil, "Error should be nil.")

	// papClient, err := newGrpcPAPClient()
	require.True(err == nil, "Error should be nil.")

	accounts, _ := aapClient.GetAccountsByName(sData.accountName)
	if len(accounts) > 0 {
		require.True(len(accounts) == 1, "One account was expected.")
		account := accounts[0]
		deletedAccount, err := aapClient.DeleteAccount(account.AccountID)
		require.True(err == nil, "Error should be nil.")
		require.Equal(account.AccountID, deletedAccount.AccountID, "Account ID should be the same.")
	}
	account, err := aapClient.CreateAccount(sData.accountName)
	require.True(err == nil, "Error should be nil.")
	require.NotNil(account, "Account should not be nil.")

	for kIdentitySource := range sData.identitySources {
		identitySource, err := aapClient.CreateIdentitySource(account.AccountID, kIdentitySource)
		require.True(err == nil, "Error should be nil.")
		require.NotNil(identitySource, "Account should not be nil.")
		kIdentityTypes := sData.identitySources[kIdentitySource]
		for kIdentityType := range kIdentityTypes {
			accountID := account.AccountID
			identitySourceID := identitySource.IdentitySourceID
			sDataIdntList := kIdentityTypes[kIdentityType]
			for i := range sDataIdntList {
				name := sDataIdntList[i]
				identity, err := aapClient.CreateIdentity(accountID, identitySourceID, kIdentityType, name)
				require.True(err == nil, "Error should be nil.")
				require.NotNil(identity, "Account should not be nil.")
			}
		}
	}

	for i := range sData.tenants {
		tenantName := sData.tenants[i]
		tenant, err := aapClient.CreateTenant(account.AccountID, tenantName)
		require.True(err == nil, "Error should be nil.")
		require.NotNil(tenant, "Tenant should not be nil.")
	}
}

// TestSeedData tests the creation of a data sample.
func TestSeedData(t *testing.T) {
	if !seedDataEnabled() {
		t.Skip("skipping test; E2E env var not set correctly")
	}
	require := require.New(t)
	createSeedData(require, &seedData{
		accountName: "car-rental",
		identitySources: map[string]map[string][]string{"google-workspace": {
			"user": {"nicolagallo", "robertobianchi"},
			"role": {"rentalagent", "returnagent"}},
		},
		tenants:      []string{"companya", "companyb", "companyc"},
		repositories: map[string]string{"car-rental": "car-rental"},
	})
	createSeedData(require, &seedData{
		accountName: "help-desk",
		identitySources: map[string]map[string][]string{"google-workspace": {
			"user": {"mariorossi"},
			"role": {"support"}},
		},
		tenants:      []string{"companya", "companyb"},
		repositories: map[string]string{"help-desk": "help-desk"},
	})
}
