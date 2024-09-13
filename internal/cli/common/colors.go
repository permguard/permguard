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

import "fmt"

// WhiteString returns the white string.
func WhiteString(text string) string {
	return fmt.Sprintf("\033[37m%s\033[0m", text)
}

// RedString returns the red string.
func RedString(text string) string {
	return fmt.Sprintf("\033[31m%s\033[0m", text)
}

// YellowString returns the red string.
func YellowString(text string) string {
	return fmt.Sprintf("\033[33m%s\033[0m", text)
}

// YellowDigit returns the yellow digit.
func YellowDigit(digit int) string {
	return fmt.Sprintf("\033[33m%d\033[0m", digit)
}

// GreenString returns the green string.
func GreenString(text string) string {
	return fmt.Sprintf("\033[32m%s\033[0m", text)
}

// BlueString returns the blue string.
func BlueString(text string) string {
	return fmt.Sprintf("\033[34m%s\033[0m", text)
}

func PinkString(text string) string {
	return fmt.Sprintf("\033[35m%s\033[0m", text)
}

// CyanString returns the cyan string.
func CyanString(text string) string {
	return fmt.Sprintf("\033[36m%s\033[0m", text)
}
