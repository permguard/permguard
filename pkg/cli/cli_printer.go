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
	"fmt"
	"net"
	"reflect"
	"sort"
	"strings"

	"github.com/fatih/color"
	"google.golang.org/grpc/status"

	azcopier "github.com/permguard/permguard-core/pkg/extensions/copier"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// errorMessageCodeMsg is the error message code message.
	errorMessageCodeMsg = "[%s] %s"
)

const (
	// OutputTerminal is the text output.
	OutputTerminal = "TERMINAL"
	// OutputJSON is the json output.
	OutputJSON = "JSON"
)

// CliPrinter is the cli printer.
type CliPrinter interface {
	// Print prints the output.
	Print(output map[string]any)
	// Error prints the error.
	Error(err error)
	// ErrorWithOutput prints the error with the output.
	ErrorWithOutput(output map[string]any, err error)
}

// CliPrinterTerminal is the cli printer.
type CliPrinterTerminal struct {
	verbose bool
	output  string
}

// NewCliPrinterTerminal returns a new cli printer.
func NewCliPrinterTerminal(verbose bool, output string) (*CliPrinterTerminal, error) {
	out := strings.ToUpper(output)
	if out != OutputTerminal && out != OutputJSON {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliGeneric, "cli: invalid output")
	}
	return &CliPrinterTerminal{
		verbose: verbose,
		output:  strings.ToUpper(output),
	}, nil
}

// printJSON prints the output as json.
func (cp *CliPrinterTerminal) printJSON(output map[string]any) {
	jsonData, err := json.Marshal(output)
	if err != nil {
		return
	}
	fmt.Println(string(jsonData))
}

// printValue prints the value.
func (cp *CliPrinterTerminal) printValue(key string, value any) {
	if value == nil || (reflect.TypeOf(value).Kind() == reflect.String && value.(string) == "") {
		green := color.New(color.FgGreen)
		green.Println(key)
		return
	}
	switch v := value.(type) {
	case map[string]any:
		green := color.New(color.FgGreen)
		if key != "" {
			green.Println(key + ":")
		}
		for k, val := range v {
			cp.printValue("\t"+k, val)
		}
	default:
		green := color.New(color.FgGreen)
		if key != "" {
			green.Printf("%s: ", key)
		}
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
func (cp *CliPrinterTerminal) printTerminal(output map[string]any, isError bool) {
	keys := make([]string, 0, len(output))
	for k := range output {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if isError {
			color.Red("%s: %s\n", k, output[k])
		} else {
			cp.printValue(k, output[k])
		}
	}
}

// Print prints the output.
func (cp *CliPrinterTerminal) Print(output map[string]any) {
	switch cp.output {
	case OutputJSON:
		if output == nil {
			output = make(map[string]any)
		}
		cp.printJSON(output)
	case OutputTerminal:
		fallthrough
	default:
		if output == nil {
			return
		}
		cp.printTerminal(output, false)
	}
}

// extractCodeAndMessage takes an input string and returns the code and the message as separate strings.
func (cp *CliPrinterTerminal) extractCodeAndMessage(input string) (string, string, error) {
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

// createOutputWithputError creates the output with the error.
func (cp *CliPrinterTerminal) createOutputWithputError(code string, msg string) map[string]any {
	var output map[string]any
	errCode := code
	errMsg := msg
	if cp.verbose {
		if cp.output == OutputJSON {
			output = map[string]any{"errorCode": errCode, "errorMessage": errMsg}
		} else {
			output = map[string]any{"error": fmt.Sprintf(errorMessageCodeMsg, errCode, errMsg)}
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
			output = map[string]any{"error": fmt.Sprintf(errorMessageCodeMsg, code, message)}
		}
	}
	return output
}

// createOutputWithError creates the output with the error.
func (cp *CliPrinterTerminal) createOutputWithError(errInputMsg string) map[string]any {
	var output map[string]any
	code := "00000"
	if cp.verbose {
		if cp.output == OutputJSON {
			output = map[string]any{"errorCode": code, "errorMessage": errInputMsg}
		} else {
			output = map[string]any{"error": fmt.Sprintf(errorMessageCodeMsg, code, errInputMsg)}

		}
	} else {
		message := "unknown error"
		if cp.output == OutputJSON {
			output = map[string]any{"errorCode": code, "errorMessage": message}
		} else {
			output = map[string]any{"error": fmt.Sprintf(errorMessageCodeMsg, code, message)}
		}
	}
	return output
}

// Error prints the output.
func (cp *CliPrinterTerminal) Error(err error) {
	var output map[string]any
	cp.ErrorWithOutput(output, err)
}

// ErrorWithOutput prints the error with the output.
func (cp *CliPrinterTerminal) ErrorWithOutput(output map[string]any, err error) {
	if _, ok := err.(*net.OpError); ok {
		err = fmt.Errorf("server cannot be reached")
	}
	if output == nil {
		output = make(map[string]any)
	}
	var errorOutput map[string]any
	if err != nil {
		var errInputMsg string
		if stsErr, ok := status.FromError(err); ok {
			errInputMsg = stsErr.Message()
		} else {
			errInputMsg = err.Error()
		}
		code, msg, err := cp.extractCodeAndMessage(errInputMsg)
		if err != nil {
			errorOutput = cp.createOutputWithError(errInputMsg)
		} else {
			errorOutput = cp.createOutputWithputError(code, msg)
		}
	}
	if len(errorOutput) > 0 {
		output = azcopier.MergeMaps(output, errorOutput)
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
