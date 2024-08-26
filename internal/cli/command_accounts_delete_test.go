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

package cli

import (
	"fmt"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/mock"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azconfigs "github.com/permguard/permguard/pkg/configs"
	aztestutils "github.com/permguard/permguard/internal/cli/testutils"
	azmocks "github.com/permguard/permguard/internal/cli/testutils/mocks"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// TestDeleteCommandForAccountsDelete tests the deleteCommandForAccountsDelete function.
func TestDeleteCommandForAccountsDelete(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official PermGuard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command deletes an account."}
	aztestutils.BaseCommandTest(t, createCommandForAccountDelete, args, false, outputs)
}

// TestCliAccountsDeleteWithError tests the command for creating an account with an error.
func TestCliAccountsDeleteWithError(t *testing.T) {
	tests := []string {
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"accounts", "delete", "--account", "581616507495", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set(azconfigs.FlagName(flagPrefixAAP, flagSuffixAAPTarget), "localhost:9092")

		depsMocks := azmocks.NewCliDependenciesMock()
		cmd := createCommandForAccountDelete(depsMocks, v)
		cmd.PersistentFlags().StringP(flagOutput, flagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(flagVerbose, flagVerboseShort, false, "true for verbose output")

		aapClient := azmocks.NewGrpcAAPClientMock()
		aapClient.On("DeleteAccount", mock.Anything).Return(nil, azerrors.ErrClientParameter)

		printerMock := azmocks.NewPrinterMock()
		printerMock.On("Error", azerrors.ErrClientParameter).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcAAPClient", mock.Anything).Return(aapClient, nil)

		aztestutils.BaseCommandWithParamsTest(t, v, cmd, args, true, outputs)
		printerMock.AssertCalled(t, "Error", azerrors.ErrClientParameter)
	}
}

// TestCliAccountsDeleteWithSuccess tests the command for creating an account with an error.
func TestCliAccountsDeleteWithSuccess(t *testing.T) {
	tests := []string {
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"accounts", "delete", "--account", "581616507495", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set("output", outputType)
		v.Set(azconfigs.FlagName(flagPrefixAAP, flagSuffixAAPTarget), "localhost:9092")

		depsMocks := azmocks.NewCliDependenciesMock()
		cmd := createCommandForAccountDelete(depsMocks, v)
		cmd.PersistentFlags().StringP(flagOutput, flagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(flagVerbose, flagVerboseShort, false, "true for verbose output")

		aapClient := azmocks.NewGrpcAAPClientMock()
		account := &azmodels.Account{
			AccountID: 581616507495,
			Name: "mycorporate",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		aapClient.On("DeleteAccount", mock.Anything).Return(account, nil)

		printerMock := azmocks.NewPrinterMock()
		outputPrinter := map[string]any{ }

		if outputType == "terminal" {
			accountID := fmt.Sprintf("%d", account.AccountID)
			outputPrinter[accountID] = account.Name
		} else {
			outputPrinter["accounts"] = []*azmodels.Account{account}
		}
		printerMock.On("Print", outputPrinter).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcAAPClient", mock.Anything).Return(aapClient, nil)

		aztestutils.BaseCommandWithParamsTest(t, v, cmd, args, false, outputs)
		printerMock.AssertCalled(t, "Print", outputPrinter)
	}
}
