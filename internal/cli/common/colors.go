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
	"github.com/fatih/color"
)

// NormalText returns the nomarl text string.
func NormalText(text string) string {
	out := color.New(color.FgWhite)
	return out.Sprintf(text)
}

// ErrorText returns the error string.
func ErrorText(text string) string {
	out := color.New(color.FgRed)
	return out.Sprintf(text)
}

// KeywordText returns the keyword string.
func KeywordText(text string) string {
	out := color.New(color.FgMagenta)
	return out.Sprintf(text)
}

// IDText returns the ID string.
func IDText(text string) string {
	out := color.New(color.FgCyan)
	return out.Sprintf(text)
}

// FileText returns the text string.
func FileText(text string) string {
	out := color.New(color.FgYellow)
	return out.Sprintf(text)
}

// NumberText returns the yellow digit.
func NumberText(digit int) string {
	out := color.New(color.FgGreen)
	return out.Sprintf("%d", digit)
}
