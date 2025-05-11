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

	"github.com/permguard/permguard/common/pkg/extensions/copier"
	cerrors "github.com/permguard/permguard/pkg/core/errors"
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
	// Print prints the message.
	Print(message string)
	// PrintMap prints the output.
	PrintMap(output map[string]any)
	// Println prints the message.
	Println(message string)
	// Println prints the output.
	PrintlnMap(output map[string]any)
	// Error prints the error.
	Error(err error)
	// ErrorWithOutput prints the error with the output.
	ErrorWithOutput(output map[string]any, err error)
}

// convertToSnakeCase converts a string to snake_case
func convertToSnakeCase(str string) string {
	var result []rune
	for i, r := range str {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result = append(result, '_')
		}
		result = append(result, r)
	}
	return strings.ToLower(string(result))
}

// Recursively process the structure or map to convert keys to snake_case
func convertKeysToSnakeCase(data any) any {
	if reflect.TypeOf(data).Kind() == reflect.Map {
		newMap := make(map[string]any)
		for k, v := range data.(map[string]any) {
			newKey := convertToSnakeCase(k)
			newMap[newKey] = convertKeysToSnakeCase(v)
		}
		return newMap
	}
	if reflect.TypeOf(data).Kind() == reflect.Struct {
		newMap := make(map[string]any)
		v := reflect.ValueOf(data)
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			newKey := convertToSnakeCase(field.Name)
			newMap[newKey] = convertKeysToSnakeCase(v.Field(i).Interface())
		}
		return newMap
	}
	return data
}

// marshalWithSnakeCase marshals a struct into JSON with snake_case keys
func marshalWithSnakeCase(v any) ([]byte, error) {
	processedData := convertKeysToSnakeCase(v)
	return json.Marshal(processedData)
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
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrCliGeneric, "invalid output")
	}
	return &CliPrinterTerminal{
		verbose: verbose,
		output:  strings.ToUpper(output),
	}, nil
}

// printJSON prints the output as json.
func (cp *CliPrinterTerminal) printJSON(output map[string]any) {
	jsonData, err := marshalWithSnakeCase(output)
	if err != nil {
		return
	}
	fmt.Println(string(jsonData))
}

// printValue prints the value.
func (cp *CliPrinterTerminal) printValue(key string, value any, newLine bool) {
	if value == nil || (reflect.TypeOf(value).Kind() == reflect.String && value.(string) == "") {
		keyColor := color.New(color.FgHiBlack)
		keyColor.Println(key)
		return
	}
	switch v := value.(type) {
	case map[string]any:
		keyColor := color.New(color.FgHiBlack)
		if key != "" {
			keyColor.Println(key + ":")
		}
		for k, val := range v {
			cp.printValue("\t"+k, val, newLine)
		}
	default:
		keyColor := color.New(color.FgHiBlack)
		if key != "" {
			keyColor.Printf("%s: ", key)
		}
		if reflect.TypeOf(v).Kind() == reflect.Slice && reflect.TypeOf(v).Elem().Kind() == reflect.String {
			white := color.New(color.FgYellow)
			array := v.([]string)
			result := strings.Join(array, ", ")
			if newLine {
				white.Println(result)
			} else {
				white.Print(result)
			}
		} else {
			white := color.New(color.Reset)
			if newLine {
				white.Println(v)
			} else {
				white.Print(v)
			}
		}
	}
}

// printTerminal prints the output as terminal text.
func (cp *CliPrinterTerminal) printTerminal(output map[string]any, isError bool, newLine bool) {
	keys := make([]string, 0, len(output))
	for k := range output {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if isError {
			color.Red("%s: %s\n", k, output[k])
		} else {
			cp.printValue(k, output[k], newLine)
		}
	}
}

// Print prints the output.
func (cp *CliPrinterTerminal) Print(message string) {
	cp.PrintMap(map[string]any{"": message})
}

// Print prints the output.
func (cp *CliPrinterTerminal) PrintMap(output map[string]any) {
	cp.print(output, false)
}

// Print prints the output.
func (cp *CliPrinterTerminal) Println(message string) {
	cp.PrintlnMap(map[string]any{"": message})
}

// Println prints the output.
func (cp *CliPrinterTerminal) PrintlnMap(output map[string]any) {
	cp.print(output, true)
}

// print prints the output.
func (cp *CliPrinterTerminal) print(output map[string]any, newLine bool) {
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
		cp.printTerminal(output, false, newLine)
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
func (cp *CliPrinterTerminal) createOutputWithputError(errCode string, errMsg string) map[string]any {
	var output map[string]any
	if cp.verbose {
		if cp.output == OutputJSON {
			output = map[string]any{"errorCode": errCode, "errorMessage": errMsg}
		} else {
			output = map[string]any{"error": fmt.Sprintf(errorMessageCodeMsg, errCode, errMsg)}
		}
	} else {
		sysErr := cerrors.NewSystemError(errCode).(cerrors.SystemError)
		if cp.output == OutputJSON {
			output = map[string]any{"errorCode": sysErr.Code(), "errorMessage": sysErr.Message()}
		} else {
			output = map[string]any{"error": fmt.Sprintf(errorMessageCodeMsg, sysErr.Code(), sysErr.Message())}
		}
	}
	return output
}

// createOutputWithError creates the output with the error.
func (cp *CliPrinterTerminal) createOutputWithError(errInputMsg string) map[string]any {
	var output map[string]any
	code := cerrors.ZeroErrorCode
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
		output = copier.MergeMaps(output, errorOutput)
	}
	switch cp.output {
	case OutputJSON:
		cp.printJSON(output)
	case OutputTerminal:
		fallthrough
	default:
		cp.printTerminal(output, true, true)
	}
}
