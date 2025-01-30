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
	"time"

	"github.com/fatih/color"
)

// LogHeaderText returns the log header text.
func LogHeaderText(text string) string {
	out := color.New(color.FgWhite)
	return out.Sprintf("%s", text)
}

// LogErrorText returns the log error text.
func LogErrorText(text string) string {
	out := color.New(color.FgRed)
	return out.Sprintf("%s", text)
}

// TimeStampText returns the timestamp text.
func BoolText(text bool) string {
	out := color.New(color.FgGreen)
	if !text {
		out = color.New(color.FgRed)
	}
	return out.Sprintf("%t", text)
}

// TimeStampText returns the timestamp text.
func TimeStampText(text string) string {
	out := color.New(color.FgBlue)
	return out.Sprintf("%s", text)
}

// DateText returns the date text.
func DateText(date time.Time) string {
	out := color.New(color.FgYellow)
	return out.Sprintf("%s", date)
}

// NormalText returns the normal text.
func NormalText(text string) string {
	out := color.New(color.FgWhite)
	return out.Sprintf("%s", text)
}

// KeywordText returns the keyword text.
func KeywordText(text string) string {
	out := color.New(color.FgHiMagenta)
	return out.Sprintf("%s", text)
}

// CliCommandText returns the cli command text.
func CliCommandText(text string) string {
	out := color.New(color.FgHiGreen)
	return out.Sprintf("%s", text)
}

// IDText returns the ID text.
func IDText(text string) string {
	out := color.New(color.FgHiCyan)
	return out.Sprintf("%s", text)
}

// NameText returns the name text.
func NameText(text string) string {
	out := color.New(color.FgHiYellow)
	return out.Sprintf("%s", text)
}

// LanguageText returns the language text.
func LanguageText(text string) string {
	out := color.New(color.FgHiGreen)
	return out.Sprintf("%s", text)
}

// LanguageText returns the language text.
func LanguageKeywordText(text string) string {
	out := color.New(color.FgHiWhite)
	return out.Sprintf("%s", text)
}

// RemoteOperationText returns the remote operation text.
func RemoteOperationText(text string) string {
	out := color.New(color.FgHiYellow)
	return out.Sprintf("%s", text)
}

// FileText returns the file text.
func FileText(text string) string {
	out := color.New(color.FgHiYellow)
	return out.Sprintf("%s", text)
}

// NumberText returns number text.
func NumberText(digit int) string {
	out := color.New(color.FgHiGreen)
	return out.Sprintf("%d", digit)
}

// BigNumberText returns big number text.
func BigNumberText(digit int64) string {
	out := color.New(color.FgHiGreen)
	return out.Sprintf("%d", digit)
}

// UnchangedText returns the unchanged text.
func UnchangedText(text string) string {
	out := color.New(color.FgHiWhite)
	return out.Sprintf("%s", text)
}

// CreateText returns the create text.
func CreateText(text string) string {
	out := color.New(color.FgHiGreen)
	return out.Sprintf("%s", text)
}

// ModifyText returns the modify text.
func ModifyText(text string) string {
	out := color.New(color.FgHiYellow)
	return out.Sprintf("%s", text)
}

// DeleteText returns the delete text.
func DeleteText(text string) string {
	out := color.New(color.FgHiRed)
	return out.Sprintf("%s", text)
}
