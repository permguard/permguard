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

package errors

import (
	"fmt"
	"strings"
	"unicode"
)

var errorCodes = map[string]string{
	// 00000: Unknown Errors
	ZeroErrorCode: "core: unknown error",

	// 001xx: Implementation Errors
	"00100": "code: generic error",
	"00101": "code: feature not implemented",

	// 01xxx: Configuration Errors
	"01000": "config: generic error",

	// 04xxx: Client Errors
	"04000": "client: generic error",

	// 041xx: Client Parameter Errors
	"04100": "client: invalid client parameter",
	"04101": "client: invalid pagination parameter",

	// 041xx: Client Entity Errors
	"04110": "client: invalid entity",
	"04111": "client: invalid ID",
	"04112": "client: invalid UUID",
	"04113": "client: invalid name",
	"04114": "client: entity not found",
	"04115": "client: update conflict",
	"04116": "client: invalid SHA256 hash",

	// 05xxx: Server Errors
	"05000": "server: generic error",
	"05001": "server: infrastructure error",

	// 051xx: Storage Errors
	"05100": "storage: generic error",
	"05101": "storage: entity mapping error",
	"05110": "storage: constraint error",
	"05111": "storage: foreign key constraint violation",
	"05112": "storage: unique constraint violation",
	"05120": "storage: entity not found in storage",

	// 06xxx: Language Errors
	"06000": "language: generic error",
	"06100": "language: generic object error",
	"06200": "language: generic file error",
	"06300": "language: generic syntax error",
	"06400": "language: generic semantic error",

	// 07xxx: Policy Server Errors
	"07100": "pdp: generic error",
	"07110": "pdp: authorization check error",
	"07111": "pdp: authorization check bad request error",
	"07112": "pdp: authorization check evaluation error",

	// 08xxx: Command Line Interface Errors
	"08000": "cli: generic error",
	"08001": "cli: invalid configuration",
	"08002": "cli: invalid arguments",
	"08003": "cli: invalid input",
	"08004": "cli: not a permguard workspace directory",
	"08005": "cli: record already exists",
	"08006": "cli: record not found",
	"08007": "cli: record is malformed",

	// 081xx: Command Line Interface File System Errors
	"08100": "cli: file system error",
	"08101": "cli: operation on directory failed",
	"08102": "cli: operation on file failed",
	"08110": "cli: workspace operation failed",
	"08111": "cli: workspace invalid head",

	// 09xxx: Plugin Errors
	"09000": "plugin: generic error",
}

const (
	// ZeroErrorCode is the zero error code.
	ZeroErrorCode = "00000"
	// Error mask for the generic error classes.
	ErrorCodeMaskGeneric = "00xxx"
	// Error mask for the code implementation errors.
	ErrorCodeMaskImplementation = "001xx"
	// Error mask for the configuration error class.
	ErrorCodeMaskConfiguration = "01xxx"
	// Error mask for the client error class.
	ErrorCodeMaskClient = "04xxx"
	// Error mask for the server error class.
	ErrorCodeMaskServer = "05xxx"
	// Error mask for the plugin error class.
	ErrorCodeMaskPlugin = "09xxx"
)

var (
	// 00000 generic system error.
	ErrUnknown error = NewSystemError(ZeroErrorCode)
	// 001xx implementation errors.
	ErrImplementation error = NewSystemError("00100")
	ErrNotImplemented error = NewSystemError("00101")
	// 01xxx configuration errors.
	ErrConfigurationGeneric error = NewSystemError("01000")
	// 04xxx client errors.
	ErrClientGeneric        error = NewSystemError("04000")
	ErrClientParameter      error = NewSystemError("04100")
	ErrClientPagination     error = NewSystemError("04101")
	ErrClientEntity         error = NewSystemError("04110")
	ErrClientID             error = NewSystemError("04111")
	ErrClientUUID           error = NewSystemError("04112")
	ErrClientName           error = NewSystemError("04113")
	ErrClientNotFound       error = NewSystemError("04114")
	ErrClientUpdateConflict error = NewSystemError("04115")
	ErrClientSHA256         error = NewSystemError("04116")
	// 05xxx server errors.
	ErrServerGeneric               error = NewSystemError("05000")
	ErrServerInfrastructure        error = NewSystemError("05001")
	ErrStorageGeneric              error = NewSystemError("05100")
	ErrStorageEntityMapping        error = NewSystemError("05101")
	ErrStorageConstraint           error = NewSystemError("05110")
	ErrStorageConstraintForeignKey error = NewSystemError("05111")
	ErrStorageConstraintUnique     error = NewSystemError("05112")
	ErrStorageNotFound             error = NewSystemError("05120")
	// 06xxx language.
	ErrLanguageGeneric   error = NewSystemError("06000")
	ErrObjects           error = NewSystemError("06100")
	ErrLanguageFile      error = NewSystemError("06200")
	ErrLanguageSyntax    error = NewSystemError("06300")
	ErrLanguangeSemantic error = NewSystemError("06400")
	// 07xxx: Policy Server Errors.
	ErrPdGeneric                      error = NewSystemError("07100")
	ErrPdpAuthzCheckFailed            error = NewSystemError("07110")
	ErrPdpAuthzCheckInvalidRequest    error = NewSystemError("07111")
	ErrPdpAuthzCheckEvaluationFailure error = NewSystemError("07112")
	// 08xxx: Command Line Interface Errors
	ErrCliGeneric             error = NewSystemError("08000")
	ErrCliConfiguration       error = NewSystemError("08001")
	ErrCliArguments           error = NewSystemError("08002")
	ErrCliInput               error = NewSystemError("08003")
	ErrCliWorkspaceDir        error = NewSystemError("08004")
	ErrCliRecordExists        error = NewSystemError("08004")
	ErrCliRecordNotFound      error = NewSystemError("08005")
	ErrCliRecordMalformed     error = NewSystemError("08006")
	ErrCliFileSystem          error = NewSystemError("08100")
	ErrCliDirectoryOperation  error = NewSystemError("08101")
	ErrCliFileOperation       error = NewSystemError("08102")
	ErrCliWorkspace           error = NewSystemError("08110")
	ErrCliWorkspaceInvaliHead error = NewSystemError("08111")
	// 09xxx plugin errors.
	ErrPluginGeneric error = NewSystemError("09000")
)

// isErrorCodeDefined checks if the error code has been defined.
func isErrorCodeDefined(code string) bool {
	return errorCodes[code] != ""
}

// isValidErrorCodeFormat checks if the error code is in the correct format.
func isValidErrorCodeFormat(input string) bool {
	if len(input) != 5 {
		return false
	}
	for _, r := range input {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// getSuperClassFromCodeWithIndex returns the superclass of the error code with the index.
func getSuperClassFromCodeWithIndex(code string, index int) string {
	if index < 2 || index > 3 {
		index = 2
	}
	superclassCode := code[:index]
	for i := index; i < len(code); i++ {
		superclassCode += "0"
	}
	errorCode := errorCodes[superclassCode]
	if errorCode == "" {
		return ZeroErrorCode
	}
	return superclassCode
}

// getSuperClassFromCode returns the superclass of the error code.
func getSuperClassFromCode(code string) string {
	if !isValidErrorCodeFormat(code) {
		return ZeroErrorCode
	}
	classCode := getSuperClassFromCodeWithIndex(code, 3)
	if classCode != ZeroErrorCode {
		return classCode
	}
	return getSuperClassFromCodeWithIndex(code, 2)
}

// transformErroMessageString transforms the error message string.
func transformErroMessageString(input, errorMessage string) string {
	parts := strings.Split(input, ":")
	if len(parts) == 0 {
		return ""
	}
	firstPart := strings.TrimSpace(parts[0])
	return fmt.Sprintf("%s: %s", firstPart, errorMessage)
}
