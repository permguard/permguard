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

	"github.com/spf13/viper"
	"github.com/stretchr/testify/mock"

	aztestutils "github.com/permguard/permguard/internal/cli/testutils"
	azmocks "github.com/permguard/permguard/internal/cli/testutils/mocks"
)

// TestCreateCommandForConfigAAPSet tests the createCommandForConfigAAPSet function.
func TestCreateCommandForConfigAAPSet(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official PermGuard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command sets the aap gRPC target."}
	aztestutils.BaseCommandTest(t, createCommandForConfigAAPSet, args, false, outputs)
}

// TestCliConfigSetAAPTarget tests the command for setting the aap target.
func TestCliConfigSetAAPTargetWithError(t *testing.T) {
	tests := []string {
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"localhost:9092", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set("output", outputType)

		depsMocks := azmocks.NewCliDependenciesMock()
		cmd := createCommandForConfigAAPSet(depsMocks, v)
		cmd.PersistentFlags().StringP(flagOutput, flagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(flagVerbose, flagVerboseShort, false, "true for verbose output")

		printerMock := azmocks.NewPrinterMock()
		printerMock.On("Error", mock.Anything).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)

		aztestutils.BaseCommandWithParamsTest(t, v, cmd, args, true, outputs)
	}
}

// TestCreateCommandForConfigPAPSet tests the createCommandForConfigPAPSet function.
func TestCreateCommandForConfigPAPSet(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official PermGuard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command sets the pap gRPC target."}
	aztestutils.BaseCommandTest(t, createCommandForConfigPAPSet, args, false, outputs)
}

// TestCliConfigSetPAPTarget tests the command for setting the pap target.
func TestCliConfigSetPAPTargetWithError(t *testing.T) {
	tests := []string {
		"terminal",
		"json",
	}
	for _, outputType := range tests {
		args := []string{"localhost:9092", "--output", outputType}
		outputs := []string{""}

		v := viper.New()
		v.Set("output", outputType)

		depsMocks := azmocks.NewCliDependenciesMock()
		cmd := createCommandForConfigPAPSet(depsMocks, v)
		cmd.PersistentFlags().StringP(flagOutput, flagOutputShort, outputType, "output format")
		cmd.PersistentFlags().BoolP(flagVerbose, flagVerboseShort, false, "true for verbose output")

		printerMock := azmocks.NewPrinterMock()
		printerMock.On("Error", mock.Anything).Return()

		depsMocks.On("CreatePrinter", mock.Anything, mock.Anything).Return(printerMock, nil)

		aztestutils.BaseCommandWithParamsTest(t, v, cmd, args, true, outputs)
	}
}
