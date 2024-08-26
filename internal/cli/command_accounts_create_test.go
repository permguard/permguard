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

	azconfigs "github.com/permguard/permguard/pkg/configs"
	azcli "github.com/permguard/permguard/pkg/cli"
	aztestutils "github.com/permguard/permguard/internal/cli/testutils"
	azmocks "github.com/permguard/permguard/internal/cli/testutils/mocks"
)

// TestCreateCommandForAccountsCreate tests the createCommandForAccountsCreate function.
func TestCreateCommandForAccountsCreate(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official PermGuard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command creates an account."}
	aztestutils.BaseCommandTest(t, createCommandForAccountCreate, args, false, outputs)
}

// TestCliAccountsCreateWithAnError tests the command for creating an account with an error.
func TestCliAccountsCreateWithAnError(t *testing.T) {
	args := []string{"accounts", "create", "--name", "mycorporate"}
	outputs := []string{"Usage"}

	v := viper.New()
	v.Set(azconfigs.FlagName(flagPrefixPAP, flagSuffixPAPTarget), "localhost:9091")
	depsMocks := azmocks.NewCliDependenciesMock()
	cmd := createCommandForAccountCreate(depsMocks, v)

	printer, _ := azcli.NewCliPrinter(true, azcli.OutputTerminal)
	cliCtx, _ := newCliContext(cmd, v)
	depsMocks.On("CreateContextAndPrinter", mock.Anything, mock.Anything).Return(cliCtx, printer, nil)

	aztestutils.BaseCommandWithParamsTest(t, v, cmd, args, true, outputs)
}
