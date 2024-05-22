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

// Package e2e for end-to-end tests.
package e2e

import (
	"os"
	"slices"

	aziclients "github.com/permguard/permguard/internal/agents/clients"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// seedDataEnabled returns true if the SEEDDATA environment variable is set to TRUE.
func seedDataEnabled() bool {
	return os.Getenv("SEEDDATA") == "TRUE"
}

// e2eEnabled returns true if the E2E environment variable is set to TRUE.
func e2eEnabled() bool {
	return os.Getenv("E2E") == "TRUE"
}

// hasAccount returns true if the account is in the list of accounts.
func hasAccount(accounts []azmodels.Account, account *azmodels.Account) bool {
	idx := slices.IndexFunc(accounts, func(a azmodels.Account) bool { return a.AccountID == account.AccountID })
	return idx > -1
}

// newGrpcAAPClient creates a new gRPC client for the AAP service.
func newGrpcAAPClient() (*aziclients.GrpcAAPClient, error) {
	return aziclients.NewGrpcAAPClient("localhost:9091")
}

// newGrpcPAPClient creates a new gRPC client for the PAP service.
func newGrpcPAPClient() (*aziclients.GrpcPAPClient, error) {
	return aziclients.NewGrpcPAPClient("localhost:9092")
}
