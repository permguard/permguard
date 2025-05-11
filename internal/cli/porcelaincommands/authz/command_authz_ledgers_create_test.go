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

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/porcelaincommands/testutils"
	"github.com/permguard/permguard/internal/cli/porcelaincommands/testutils/mocks"
	"github.com/permguard/permguard/pkg/cli/options"
	cerrors "github.com/permguard/permguard/pkg/core/errors"
	"github.com/permguard/permguard/pkg/transport/models/pap"
)

// TestCreateCommandForLedgersCreate tests the createCommandForLedgersCreate function.
func TestCreateCommandForLedgersCreate(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official Permguard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command creates a remote ledger."}
	testutils.BaseCommandTest(t, createCommandForLedgerCreate, args, false, outputs)
}

// TestCliLedgersCreateWithError tests the command for creating a ledger with an error.
func TestCliLedgersCreateWithError(t *testing.T) {
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
		args := []string{"ledgers", "create", "--name", "v1.0", "--output", test.OutputType}
		outputs := []string{""}

		v := viper.New()
		v.Set(options.FlagName(common.FlagPrefixPAP, common.FlagSuffixPAPTarget), "localhost:9092")

		depsMocks := mocks.NewCliDependenciesMock()
		cmd := createCommandForLedgerCreate(depsMocks, v)
		cmd.PersistentFlags().StringP(common.FlagWorkingDirectory, common.FlagWorkingDirectoryShort, ".", "work directory")
		cmd.PersistentFlags().StringP(common.FlagOutput, common.FlagOutputShort, test.OutputType, "output format")
		cmd.PersistentFlags().BoolP(common.FlagVerbose, common.FlagVerboseShort, true, "true for verbose output")

		papClient := mocks.NewGrpcPAPClientMock()
		papClient.On("CreateLedger", mock.Anything, mock.Anything, mock.Anything).Return(nil, cerrors.ErrClientParameter)

		printerMock := mocks.NewPrinterMock()
		printerMock.On("Println", mock.Anything).Return()
		printerMock.On("PrintlnMap", mock.Anything).Return()
		printerMock.On("Error", mock.Anything).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcPAPClient", mock.Anything).Return(papClient, nil)

		testutils.BaseCommandWithParamsTest(t, v, cmd, args, true, outputs)
		if test.HasError {
			printerMock.AssertCalled(t, "Error", mock.Anything)
		} else {
			printerMock.AssertNotCalled(t, "Error", mock.Anything)
		}
	}
}

// TestCliLedgersCreateWithSuccess tests the command for creating a ledger with an error.
func TestCliLedgersCreateWithSuccess(t *testing.T) {
	tests := []string{
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"ledgers", "create", "--name", "v1.0", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set("output", outputType)
		v.Set(options.FlagName(common.FlagPrefixPAP, common.FlagSuffixPAPTarget), "localhost:9092")

		depsMocks := mocks.NewCliDependenciesMock()
		cmd := createCommandForLedgerCreate(depsMocks, v)
		cmd.PersistentFlags().StringP(common.FlagWorkingDirectory, common.FlagWorkingDirectoryShort, ".", "work directory")
		cmd.PersistentFlags().StringP(common.FlagOutput, common.FlagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(common.FlagVerbose, common.FlagVerboseShort, true, "true for verbose output")

		papClient := mocks.NewGrpcPAPClientMock()
		ledger := &pap.Ledger{
			LedgerID:  "c3160a533ab24fbcb1eab7a09fd85f36",
			ZoneID:    581616507495,
			Name:      "v1.0",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		papClient.On("CreateLedger", mock.Anything, mock.Anything, mock.Anything).Return(ledger, nil)

		printerMock := mocks.NewPrinterMock()
		outputPrinter := map[string]any{}

		if outputType == "terminal" {
			ledgerID := ledger.LedgerID
			outputPrinter[ledgerID] = ledger.Name
		} else {
			outputPrinter["ledgers"] = []*pap.Ledger{ledger}
		}
		printerMock.On("PrintMap", outputPrinter).Return()
		printerMock.On("PrintlnMap", outputPrinter).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcPAPClient", mock.Anything).Return(papClient, nil)

		testutils.BaseCommandWithParamsTest(t, v, cmd, args, false, outputs)
		printerMock.AssertCalled(t, "PrintlnMap", outputPrinter)
	}
}
