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
	"github.com/spf13/viper"
)

type CliContext interface {
	// GetViper returns the viper.
	GetViper() *viper.Viper
	// GetVerbose returns true if the verbose.
	GetVerbose() bool
	// GetOutput returns the output.
	GetOutput() string
	// IsTerminalOutput returns true if the output is json.
	IsTerminalOutput() bool
	// IsJSONOutput returns true if the output is json.
	IsJSONOutput() bool
	// GetAAPTarget returns the aap target.
	GetAAPTarget() string
	// GetPAPTarget returns the pap target.
	GetPAPTarget() string
}
