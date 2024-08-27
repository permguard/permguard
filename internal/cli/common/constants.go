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

import (
	"fmt"
	"errors"

	_ "embed"
)

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

//go:embed "art.txt"
var asciiArt string

// CliLongTemplateHead is the head of the long template for the cli.
var CliLongTemplateHead = `
%s
The official PermGuard Command Line Interface - Copyright © 2022 Nitro Agility S.r.l.`

// CliLongTemplateBody is the body of the long template for the cli.
var CliLongTemplateBody = ` %s

%s
`

// CliLongTemplateFooter is the footer of the long template for the cli.
var CliLongTemplateFooter = `%s
	Find more information at: https://www.permguard.com/docs/cli/how-to-use/
	`

// BuildCliLongTemplate builds the long template for the cli.
func BuildCliLongTemplate(content string) string {
	template := fmt.Sprintf(CliLongTemplateHead, asciiArt)
	if len(content) >= 0 {
		template = fmt.Sprintf(CliLongTemplateBody, template, content)
	}
	template = fmt.Sprintf(CliLongTemplateFooter, template)
	return template
}

// ErrCommandSilent is an error that is used to indicate that the command should not print an error message.
var ErrCommandSilent = errors.New("command: silent error")
