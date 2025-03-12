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

package authz

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/mock"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	aztestutils "github.com/permguard/permguard/internal/cli/porcelaincommands/testutils"
	azmocks "github.com/permguard/permguard/internal/cli/porcelaincommands/testutils/mocks"
	azconfigs "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelspap "github.com/permguard/permguard/pkg/transport/models/pap"
)

// TestListCommandForLedgersList tests the listCommandForLedgersList function.
func TestListCommandForLedgersList(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official Permguard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command lists all remote ledgers."}
	aztestutils.BaseCommandTest(t, createCommandForLedgerList, args, false, outputs)
}

// TestCliLedgersListWithError tests the command for creating an ledger with an error.
func TestCliLedgersListWithError(t *testing.T) {
	tests := []struct {
		OutputType string
		HasError   bool
	}{
		{
			OutputType: "terminal",
			HasError:   true,
		},
		{
			OutputType: "json",
			HasError:   true,
		},
	}
	for _, test := range tests {
		args := []string{"ledgers", "list", "--ledger-id", "c3160a533ab24fbcb1eab7a09fd85f36", "--output", test.OutputType}
		outputs := []string{""}

		v := viper.New()
		v.Set(azconfigs.FlagName(aziclicommon.FlagPrefixPAP, aziclicommon.FlagSuffixPAPTarget), "localhost:9092")

		depsMocks := azmocks.NewCliDependenciesMock()
		cmd := createCommandForLedgerList(depsMocks, v)
		cmd.PersistentFlags().StringP(aziclicommon.FlagWorkingDirectory, aziclicommon.FlagWorkingDirectoryShort, ".", "work directory")
		cmd.PersistentFlags().StringP(aziclicommon.FlagOutput, aziclicommon.FlagOutputShort, test.OutputType, "output format")
		cmd.PersistentFlags().BoolP(aziclicommon.FlagVerbose, aziclicommon.FlagVerboseShort, true, "true for verbose output")

		papClient := azmocks.NewGrpcPAPClientMock()
		papClient.On("FetchLedgersBy", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, azerrors.ErrClientParameter)

		printerMock := azmocks.NewPrinterMock()
		printerMock.On("Println", mock.Anything).Return()
		printerMock.On("PrintlnMap", mock.Anything).Return()
		printerMock.On("Error", mock.Anything).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcPAPClient", mock.Anything).Return(papClient, nil)

		aztestutils.BaseCommandWithParamsTest(t, v, cmd, args, true, outputs)
		if test.HasError {
			printerMock.AssertCalled(t, "Error", mock.Anything)
		} else {
			printerMock.AssertNotCalled(t, "Error", mock.Anything)
		}
	}
}

// TestCliLedgersListWithSuccess tests the command for creating an ledger with an error.
func TestCliLedgersListWithSuccess(t *testing.T) {
	tests := []string{
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"ledgers", "list", "--ledger-id", "c3160a533ab24fbcb1eab7a09fd85f36", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set("output", outputType)
		v.Set(azconfigs.FlagName(aziclicommon.FlagPrefixPAP, aziclicommon.FlagSuffixPAPTarget), "localhost:9092")

		depsMocks := azmocks.NewCliDependenciesMock()
		cmd := createCommandForLedgerList(depsMocks, v)
		cmd.PersistentFlags().StringP(aziclicommon.FlagWorkingDirectory, aziclicommon.FlagWorkingDirectoryShort, ".", "work directory")
		cmd.PersistentFlags().StringP(aziclicommon.FlagOutput, aziclicommon.FlagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(aziclicommon.FlagVerbose, aziclicommon.FlagVerboseShort, true, "true for verbose output")

		papClient := azmocks.NewGrpcPAPClientMock()
		ledgers := []azmodelspap.Ledger{
			{
				LedgerID:  "c3160a533ab24fbcb1eab7a09fd85f36",
				ZoneID:    581616507495,
				Name:      "v1.1",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			{
				LedgerID:  "f73d25ae7b1f4f66807c3face0fee0f3",
				ZoneID:    581616507495,
				Name:      "v1.2",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		}
		papClient.On("FetchLedgersBy", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(ledgers, nil)

		printerMock := azmocks.NewPrinterMock()
		outputPrinter := map[string]any{}

		if outputType == "terminal" {
			for _, ledger := range ledgers {
				ledgerID := ledger.LedgerID
				outputPrinter[ledgerID] = ledger.Name
			}
		} else {
			outputPrinter["ledgers"] = ledgers
		}
		printerMock.On("PrintMap", outputPrinter).Return()
		printerMock.On("PrintlnMap", outputPrinter).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcPAPClient", mock.Anything).Return(papClient, nil)

		aztestutils.BaseCommandWithParamsTest(t, v, cmd, args, false, outputs)
		printerMock.AssertCalled(t, "PrintlnMap", outputPrinter)
	}
}
