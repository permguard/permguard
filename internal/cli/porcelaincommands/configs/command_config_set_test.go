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

package configs

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/mock"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/porcelaincommands/testutils"
	"github.com/permguard/permguard/internal/cli/porcelaincommands/testutils/mocks"
)

// TestCreateCommandForConfigZAPSet tests the createCommandForConfigZAPSet function.
func TestCreateCommandForConfigZAPSet(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official Permguard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command sets the zap grpc target."}
	testutils.BaseCommandTest(t, createCommandForConfigZAPSet, args, false, outputs)
}

// TestCliConfigSetZAPTarget tests the command for setting the zap target.
func TestCliConfigSetZAPTargetWithError(t *testing.T) {
	tests := []string{
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"localhost:9092", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set("output", outputType)

		depsMocks := mocks.NewCliDependenciesMock()
		cmd := createCommandForConfigZAPSet(depsMocks, v)
		cmd.PersistentFlags().StringP(common.FlagWorkingDirectory, common.FlagWorkingDirectoryShort, ".", "work directory")
		cmd.PersistentFlags().StringP(common.FlagOutput, common.FlagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(common.FlagVerbose, common.FlagVerboseShort, true, "true for verbose output")

		printerMock := mocks.NewPrinterMock()
		printerMock.On("Println", mock.Anything).Return()
		printerMock.On("PrintlnMap", mock.Anything).Return()
		printerMock.On("Error", mock.Anything).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)

		testutils.BaseCommandWithParamsTest(t, v, cmd, args, true, outputs)
	}
}

// TestCreateCommandForConfigPAPSet tests the createCommandForConfigPAPSet function.
func TestCreateCommandForConfigPAPSet(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official Permguard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command sets the pap grpc target."}
	testutils.BaseCommandTest(t, createCommandForConfigPAPSet, args, false, outputs)
}

// TestCliConfigSetPAPTarget tests the command for setting the pap target.
func TestCliConfigSetPAPTargetWithError(t *testing.T) {
	tests := []string{
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"localhost:9092", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set("output", outputType)

		depsMocks := mocks.NewCliDependenciesMock()
		cmd := createCommandForConfigPAPSet(depsMocks, v)
		cmd.PersistentFlags().StringP(common.FlagWorkingDirectory, common.FlagWorkingDirectoryShort, ".", "work directory")
		cmd.PersistentFlags().StringP(common.FlagOutput, common.FlagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(common.FlagVerbose, common.FlagVerboseShort, true, "true for verbose output")

		printerMock := mocks.NewPrinterMock()
		printerMock.On("Println", mock.Anything).Return()
		printerMock.On("PrintlnMap", mock.Anything).Return()
		printerMock.On("Error", mock.Anything).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)

		testutils.BaseCommandWithParamsTest(t, v, cmd, args, true, outputs)
	}
}
