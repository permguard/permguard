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

package common

import "errors"

const (
	ErrorMessageCliBug        = "an issue has been detected with the cli code configuration. please create a github issue with the details."
	ErrorMessageInvalidInputs = "invalid inputs"
)

const (
	FlagOutput              = "output"
	FlagOutputShort         = "o"
	FlagVerbose             = "verbose"
	FlagVerboseShort        = "v"
	FlagCommonPage          = "page"
	FlagCommonPageShort     = "p"
	FlagCommonPageSize      = "size"
	FlagCommonPageSizeShort = "s"
	FlagCommonAccountID     = "account"
	FlagCommonName          = "name"
	FlagCommonEmail         = "email"
	FlagCommonDescription   = "description"
	FlagCommonFile          = "file"
	FlagCommonFileShort     = "f"
	FlagPrefixAAP           = "aap"
	FlagSuffixAAPTarget     = "target"
	FlagPrefixPAP           = "pap"
	FlagSuffixPAPTarget     = "target"
)

// CliLongTemplate is the long template for the cli.
var CliLongTemplate = `The official PermGuard Command Line Interface
Copyright © 2022 Nitro Agility S.r.l.
%s

	Find more information at: https://www.permguard.com/docs/cli/how-to-use/`

// ErrCommandSilent is an error that is used to indicate that the command should not print an error message.
var ErrCommandSilent = errors.New("command: silent error")
