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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/fatih/color"
	"google.golang.org/grpc/status"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

const (
	// OutputTerminal is the text output.
	OutputTerminal = "TERMINAL"
	// OutputJSON is the json output.
	OutputJSON = "JSON"
)

// CliPrinter is the cli printer.
type CliPrinter struct {
	verbose bool
	output  string
}

// NewCliPrinter returns a new cli printer.
func NewCliPrinter(verbose bool, output string) (*CliPrinter, error) {
	out := strings.ToUpper(output)
	if out != OutputTerminal && out != OutputJSON {
		return nil, errors.New("cli: invalid output")
	}
	return &CliPrinter{
		verbose: verbose,
		output:  strings.ToUpper(output),
	}, nil
}

// printJSON prints the output as json.
func (cp *CliPrinter) printJSON(output map[string]any) {
	jsonData, err := json.Marshal(output)
	if err != nil {
		return
	}
	fmt.Println(string(jsonData))
}

// printValue prints the value.
func (cp *CliPrinter) printValue(key string, value interface{}) {
	if value == nil || (reflect.TypeOf(value).Kind() == reflect.String && value.(string) == "") {
		green := color.New(color.FgGreen)
		green.Println(key)
		return
	}
	switch v := value.(type) {
	case map[string]interface{}:
		green := color.New(color.FgGreen)
		green.Println(key + ":")
		for k, val := range v {
			cp.printValue("\t"+k, val)
		}
	default:
		green := color.New(color.FgGreen)
		green.Printf("%s: ", key)
		if reflect.TypeOf(v).Kind() == reflect.Slice && reflect.TypeOf(v).Elem().Kind() == reflect.String {
			white := color.New(color.FgYellow)
			array := v.([]string)
			result := strings.Join(array, ", ")
			white.Println(result)
		} else {
			white := color.New(color.FgWhite)
			white.Println(v)
		}
	}
}

// printTerminal prints the output as terminal text.
func (cp *CliPrinter) printTerminal(output map[string]any, isError bool) {
	for k, v := range output {
		if isError {
			color.Red("%s: %s\n", k, v)
		} else {
			cp.printValue(k, v)
		}
	}
}

// Print prints the output.
func (cp *CliPrinter) Print(output map[string]any) {
	switch cp.output {
	case OutputJSON:
		cp.printJSON(output)
	case OutputTerminal:
		fallthrough
	default:
		cp.printTerminal(output, false)
	}
}

// extractCodeAndMessage takes an input string and returns the code and the message as separate strings.
func (cp *CliPrinter) extractCodeAndMessage(input string) (string, string, error) {
	codePrefix := "code: "
	messagePrefix := "message: "

	codeIndex := strings.Index(input, codePrefix)
	messageIndex := strings.Index(input, messagePrefix)

	if codeIndex == -1 || messageIndex == -1 {
		return "", "", fmt.Errorf("invalid input format")
	}

	codeStart := codeIndex + len(codePrefix)
	codeEnd := strings.Index(input[codeStart:], ",")
	if codeEnd == -1 {
		return "", "", fmt.Errorf("invalid input format")
	}
	code := input[codeStart : codeStart+codeEnd]

	messageStart := messageIndex + len(messagePrefix)
	message := input[messageStart:]

	return code, message, nil
}

// Error prints the output.
func (cp *CliPrinter) Error(err error) {
	var output map[string]any
	var errMsg string
	var errCode string
	if err == nil {
		errMsg = "unknown error"
	} else {
		var errInputMsg string
		if stsErr, ok := status.FromError(err); ok {
			errInputMsg = stsErr.Message()
		} else {
			errInputMsg = err.Error()
		}
		code, msg, err := cp.extractCodeAndMessage(errInputMsg)
		if err != nil {
			code = "00000"
			if cp.verbose {
				if cp.output == OutputJSON {
					output = map[string]any{"errorCode": code, "errorMessage": errInputMsg}
				} else {
					output = map[string]any{"error": fmt.Sprintf("%s, %s", code, errInputMsg)}

				}
			} else {
				message := "unknown error"
				if cp.output == OutputJSON {
					output = map[string]any{"errorCode": code, "errorMessage": message}
				} else {
					output = map[string]any{"error": fmt.Sprintf("%s, %s", code, message)}
				}
			}
		} else {
			errCode = code
			errMsg = msg
			if cp.verbose {
				if cp.output == OutputJSON {
					output = map[string]any{"errorCode": errCode, "errorMessage": errMsg}
				} else {
					output = map[string]any{"error": fmt.Sprintf("%s, %s", errCode, errMsg)}
				}
			} else {
				code = "00000"
				message := "unknown error"
				sysErr := azerrors.ConvertToSystemError(azerrors.GetErrorFromCode(errCode))
				if sysErr == nil {
					sysErr = azerrors.ConvertToSystemError(azerrors.GetSuperClassErrorFromCode(errCode))
				}
				if sysErr != nil {
					code = sysErr.Code()
					message = sysErr.Message()
				}
				if cp.output == OutputJSON {
					output = map[string]any{"errorCode": code, "errorMessage": message}
				} else {
					output = map[string]any{"error": fmt.Sprintf("%s, %s", code, message)}
				}
			}
		}
	}
	switch cp.output {
	case OutputJSON:
		cp.printJSON(output)
	case OutputTerminal:
		fallthrough
	default:
		cp.printTerminal(output, true)
	}
}
