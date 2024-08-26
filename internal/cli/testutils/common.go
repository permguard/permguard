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

package testutils

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	azmocks "github.com/permguard/permguard/internal/cli/testutils/mocks"
	azcli "github.com/permguard/permguard/pkg/cli"
)

// BaseCommandTest tests the command.
func BaseCommandTest(t *testing.T, cmdFunc func(azcli.CliDependenciesProvider, *viper.Viper) *cobra.Command, args []string, hasError bool, outputs []string) {
	assert := assert.New(t)
	v := viper.New()

	depsMocks := azmocks.NewCliDependenciesMock()
	cmd := cmdFunc(depsMocks, v)
	assert.NotNil(cmd, "The command should not be nil")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs(args)

	err := cmd.Execute()
	if hasError {
		assert.NotNil(err, "err should not be nil")
	} else {
		assert.Nil(err, "err should be nil")
	}

	output := buf.String()
	for _, out := range outputs {
		assert.Contains(output, out)
	}
}

// BaseCommandWithParamsTest tests the command with parameters.
func BaseCommandWithParamsTest(t *testing.T, v *viper.Viper, cmd *cobra.Command, args []string, hasError bool, outputs []string) {
	assert := assert.New(t)

	assert.NotNil(cmd, "The command should not be nil")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs(args)

	err := cmd.Execute()
	if hasError {
		assert.NotNil(err, "err should not be nil")
	} else {
		assert.Nil(err, "err should be nil")
	}

	output := buf.String()
	for _, out := range outputs {
		if out == "" {
			continue
		}
		assert.Contains(output, out)
	}
}
