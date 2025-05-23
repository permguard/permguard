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

package authn

import (
	"errors"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/mock"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/porcelaincommands/testutils"
	"github.com/permguard/permguard/internal/cli/porcelaincommands/testutils/mocks"
	"github.com/permguard/permguard/pkg/cli/options"
	"github.com/permguard/permguard/pkg/transport/models/zap"
)

// TestListCommandForTenantsList tests the listCommandForTenantsList function.
func TestListCommandForTenantsList(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official Permguard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command lists all remote tenants."}
	testutils.BaseCommandTest(t, createCommandForTenantList, args, false, outputs)
}

// TestCliTenantsListWithError tests the command for creating an tenant with an error.
func TestCliTenantsListWithError(t *testing.T) {
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
		args := []string{"tenants", "list", "--tenant-id", "c3160a533ab24fbcb1eab7a09fd85f36", "--output", test.OutputType}
		outputs := []string{""}

		v := viper.New()
		v.Set(options.FlagName(common.FlagPrefixZAP, common.FlagSuffixZAPTarget), "localhost:9092")

		depsMocks := mocks.NewCliDependenciesMock()
		cmd := createCommandForTenantList(depsMocks, v)
		cmd.PersistentFlags().StringP(common.FlagWorkingDirectory, common.FlagWorkingDirectoryShort, ".", "work directory")
		cmd.PersistentFlags().StringP(common.FlagOutput, common.FlagOutputShort, test.OutputType, "output format")
		cmd.PersistentFlags().BoolP(common.FlagVerbose, common.FlagVerboseShort, true, "true for verbose output")

		zapClient := mocks.NewGrpcZAPClientMock()
		zapClient.On("FetchTenantsBy", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("operation error"))

		printerMock := mocks.NewPrinterMock()
		printerMock.On("Println", mock.Anything).Return()
		printerMock.On("PrintlnMap", mock.Anything).Return()
		printerMock.On("Error", mock.Anything).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcZAPClient", mock.Anything).Return(zapClient, nil)

		testutils.BaseCommandWithParamsTest(t, v, cmd, args, true, outputs)
		if test.HasError {
			printerMock.AssertCalled(t, "Error", mock.Anything)
		} else {
			printerMock.AssertNotCalled(t, "Error", mock.Anything)
		}
	}
}

// TestCliTenantsListWithSuccess tests the command for creating an tenant with an error.
func TestCliTenantsListWithSuccess(t *testing.T) {
	tests := []string{
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"tenants", "list", "--tenant-id", "c3160a533ab24fbcb1eab7a09fd85f36", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set("output", outputType)
		v.Set(options.FlagName(common.FlagPrefixZAP, common.FlagSuffixZAPTarget), "localhost:9092")

		depsMocks := mocks.NewCliDependenciesMock()
		cmd := createCommandForTenantList(depsMocks, v)
		cmd.PersistentFlags().StringP(common.FlagWorkingDirectory, common.FlagWorkingDirectoryShort, ".", "work directory")
		cmd.PersistentFlags().StringP(common.FlagOutput, common.FlagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(common.FlagVerbose, common.FlagVerboseShort, true, "true for verbose output")

		zapClient := mocks.NewGrpcZAPClientMock()
		tenants := []zap.Tenant{
			{
				TenantID:  "c3160a533ab24fbcb1eab7a09fd85f36",
				ZoneID:    581616507495,
				Name:      "materabranch1",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			{
				TenantID:  "f73d25ae7b1f4f66807c3face0fee0f3",
				ZoneID:    581616507495,
				Name:      "materabranch2",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		}
		zapClient.On("FetchTenantsBy", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tenants, nil)

		printerMock := mocks.NewPrinterMock()
		outputPrinter := map[string]any{}

		if outputType == "terminal" {
			for _, tenant := range tenants {
				tenantID := tenant.TenantID
				outputPrinter[tenantID] = tenant.Name
			}
		} else {
			outputPrinter["tenants"] = tenants
		}
		printerMock.On("PrintMap", outputPrinter).Return()
		printerMock.On("PrintlnMap", outputPrinter).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcZAPClient", mock.Anything).Return(zapClient, nil)

		testutils.BaseCommandWithParamsTest(t, v, cmd, args, false, outputs)
		printerMock.AssertCalled(t, "PrintlnMap", outputPrinter)
	}
}
