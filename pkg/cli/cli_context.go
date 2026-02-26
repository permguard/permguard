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

// Context defines the CLI context interface.
type Context interface {
	// Viper returns the viper.
	Viper() *viper.Viper
	// GetVerbose returns true if the verbose.
	GetVerbose() bool
	// Output returns the output.
	Output() string
	// IsTerminalOutput returns true if the output is json.
	IsTerminalOutput() bool
	// IsJSONOutput returns true if the output is json.
	IsJSONOutput() bool
	// ZAPTarget returns the zap target.
	ZAPTarget() string
	// PAPTarget returns the pap target.
	PAPTarget() string
}
