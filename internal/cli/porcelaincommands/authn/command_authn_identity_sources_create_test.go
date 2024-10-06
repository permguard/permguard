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
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/mock"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	aztestutils "github.com/permguard/permguard/internal/cli/porcelaincommands/testutils"
	azmocks "github.com/permguard/permguard/internal/cli/porcelaincommands/testutils/mocks"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
	azconfigs "github.com/permguard/permguard/pkg/cli/options"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// TestCreateCommandForIdentitySourcesCreate tests the createCommandForIdentitySourcesCreate function.
func TestCreateCommandForIdentitySourcesCreate(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official Permguard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command creates a remote identity source."}
	aztestutils.BaseCommandTest(t, createCommandForIdentitySourceCreate, args, false, outputs)
}

// TestCliIdentitySourcesCreateWithError tests the command for creating a identitysource with an error.
func TestCliIdentitySourcesCreateWithError(t *testing.T) {
	tests := []string{
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"identitysources", "create", "--name", "google", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set(azconfigs.FlagName(aziclicommon.FlagPrefixAAP, aziclicommon.FlagSuffixAAPTarget), "localhost:9092")

		depsMocks := azmocks.NewCliDependenciesMock()
		cmd := createCommandForIdentitySourceCreate(depsMocks, v)
		cmd.PersistentFlags().StringP(aziclicommon.FlagWorkingDirectory, aziclicommon.FlagWorkingDirectoryShort, ".", "work directory")
		cmd.PersistentFlags().StringP(aziclicommon.FlagOutput, aziclicommon.FlagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(aziclicommon.FlagVerbose, aziclicommon.FlagVerboseShort, false, "true for verbose output")

		aapClient := azmocks.NewGrpcAAPClientMock()
		aapClient.On("CreateIdentitySource", mock.Anything, mock.Anything).Return(nil, azerrors.ErrClientParameter)

		printerMock := azmocks.NewPrinterMock()
		printerMock.On("Error", azerrors.ErrClientParameter).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcAAPClient", mock.Anything).Return(aapClient, nil)

		aztestutils.BaseCommandWithParamsTest(t, v, cmd, args, true, outputs)
		printerMock.AssertCalled(t, "Error", azerrors.ErrClientParameter)
	}
}

// TestCliIdentitySourcesCreateWithSuccess tests the command for creating a identitysource with an error.
func TestCliIdentitySourcesCreateWithSuccess(t *testing.T) {
	tests := []string{
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"identitysources", "create", "--name", "google", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set("output", outputType)
		v.Set(azconfigs.FlagName(aziclicommon.FlagPrefixAAP, aziclicommon.FlagSuffixAAPTarget), "localhost:9092")

		depsMocks := azmocks.NewCliDependenciesMock()
		cmd := createCommandForIdentitySourceCreate(depsMocks, v)
		cmd.PersistentFlags().StringP(aziclicommon.FlagWorkingDirectory, aziclicommon.FlagWorkingDirectoryShort, ".", "work directory")
		cmd.PersistentFlags().StringP(aziclicommon.FlagOutput, aziclicommon.FlagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(aziclicommon.FlagVerbose, aziclicommon.FlagVerboseShort, false, "true for verbose output")

		aapClient := azmocks.NewGrpcAAPClientMock()
		identitysource := &azmodels.IdentitySource{
			IdentitySourceID: "c3160a533ab24fbcb1eab7a09fd85f36",
			AccountID:        581616507495,
			Name:             "google",
			CreatedAt:        time.Now(),
			UpdatedAt:        time.Now(),
		}
		aapClient.On("CreateIdentitySource", mock.Anything, mock.Anything).Return(identitysource, nil)

		printerMock := azmocks.NewPrinterMock()
		outputPrinter := map[string]any{}

		if outputType == "terminal" {
			identitysourceID := identitysource.IdentitySourceID
			outputPrinter[identitysourceID] = identitysource.Name
		} else {
			outputPrinter["identity_sources"] = []*azmodels.IdentitySource{identitysource}
		}
		printerMock.On("Print", outputPrinter).Return()
		printerMock.On("Println", outputPrinter).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcAAPClient", mock.Anything).Return(aapClient, nil)

		aztestutils.BaseCommandWithParamsTest(t, v, cmd, args, false, outputs)
		printerMock.AssertCalled(t, "Print", outputPrinter)
	}
}
