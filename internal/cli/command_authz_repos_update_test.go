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

// TestUpdateCommandForRepositoriesUpdate tests the updateCommandForRepositoriesUpdate function.
func TestUpdateCommandForRepositoriesUpdate(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official PermGuard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command updates a repository."}
	aztestutils.BaseCommandTest(t, createCommandForRepositoryUpdate, args, false, outputs)
}

// TestCliRepositoriesUpdateWithError tests the command for creating a repository with an error.
func TestCliRepositoriesUpdateWithError(t *testing.T) {
	tests := []string {
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"repositories", "update", "--repositoryid", "c3160a533ab24fbcb1eab7a09fd85f36", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set(azconfigs.FlagName(flagPrefixPAP, flagSuffixPAPTarget), "localhost:9092")

		depsMocks := azmocks.NewCliDependenciesMock()
		cmd := createCommandForRepositoryUpdate(depsMocks, v)
		cmd.PersistentFlags().StringP(flagOutput, flagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(flagVerbose, flagVerboseShort, false, "true for verbose output")

		papClient := azmocks.NewGrpcPAPClientMock()
		papClient.On("UpdateRepository", mock.Anything).Return(nil, azerrors.ErrClientParameter)

		printerMock := azmocks.NewPrinterMock()
		printerMock.On("Error", azerrors.ErrClientParameter).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcPAPClient", mock.Anything).Return(papClient, nil)

		aztestutils.BaseCommandWithParamsTest(t, v, cmd, args, true, outputs)
		printerMock.AssertCalled(t, "Error", azerrors.ErrClientParameter)
	}
}

// TestCliRepositoriesUpdateWithSuccess tests the command for creating a repository with an error.
func TestCliRepositoriesUpdateWithSuccess(t *testing.T) {
	tests := []string {
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"repositories", "update", "--repositoryid", "c3160a533ab24fbcb1eab7a09fd85f36", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set("output", outputType)
		v.Set(azconfigs.FlagName(flagPrefixPAP, flagSuffixPAPTarget), "localhost:9092")

		depsMocks := azmocks.NewCliDependenciesMock()
		cmd := createCommandForRepositoryUpdate(depsMocks, v)
		cmd.PersistentFlags().StringP(flagOutput, flagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(flagVerbose, flagVerboseShort, false, "true for verbose output")

		papClient := azmocks.NewGrpcPAPClientMock()
		repository := &azmodels.Repository{
			RepositoryID: "c3160a533ab24fbcb1eab7a09fd85f36",
			AccountID: 581616507495,
			Name: "materabranch",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		papClient.On("UpdateRepository", mock.Anything).Return(repository, nil)

		printerMock := azmocks.NewPrinterMock()
		outputPrinter := map[string]any{ }

		if outputType == "terminal" {
			repositoryID := repository.RepositoryID
			outputPrinter[repositoryID] = repository.Name
		} else {
			outputPrinter["repositories"] = []*azmodels.Repository{repository}
		}
		printerMock.On("Print", outputPrinter).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)
		depsMocks.On("CreateGrpcPAPClient", mock.Anything).Return(papClient, nil)

		aztestutils.BaseCommandWithParamsTest(t, v, cmd, args, false, outputs)
		printerMock.AssertCalled(t, "Print", outputPrinter)
	}
}
