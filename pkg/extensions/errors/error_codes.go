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

var errorCodes = map[string]string{
	// 00000: Unknown Errors
	"00000": "core: unknown error",

	// 001xx: Implementation Errors
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

	// 05xxx: Server Errors
	"05000": "server: generic error",
	"05001": "server: infrastructure error",

	// 051xx: Storage Errors
	"05100": "stroage: generic error",
	"05101": "storage: entity mapping error",
	"05110": "storage: constraint error",
	"05111": "stroage: foreign key constraint violation",
	"05112": "stroage: unique constraint violation",
	"05120": "stroage: entity not found in storage",

	// 08xxx: Command Line Interface Errors
	"08000": "cli: generic error",

	// 081xx: Command Line Interface File System Errors
	"08100": "cli: file system error",
	"08101": "cli: operation on directory failed",
	"08102": "cli: operation on file failed",

	// 09xxx: Plugin Errors
	"09000": "plugin: generic error",
}

const (
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
	ErrUnknown error = NewSystemError("00000")
	// 001xx implementation errors.
	ErrNotImplemented error = NewSystemError("00101")
	// 01xxx configuration errors.
	ErrConfigurationGeneric error = NewSystemError("01000")
	// 04xxx client errors.
	ErrClientGeneric 	error = NewSystemError("04000")
	ErrClientParameter  error = NewSystemError("04100")
	ErrClientPagination error = NewSystemError("04101")
	ErrClientEntity 	error = NewSystemError("04110")
	ErrClientID     	error = NewSystemError("04111")
	ErrClientUUID   	error = NewSystemError("04112")
	ErrClientName   	error = NewSystemError("04113")
	// 05xxx server errors.
	ErrServerGeneric       			error = NewSystemError("05000")
	ErrServerInfrastructure			error = NewSystemError("05001")
	ErrStorageGeneric      			error = NewSystemError("05100")
	ErrStorageEntityMapping			error = NewSystemError("05101")
	ErrStorageConstraint   			error = NewSystemError("05110")
	ErrStorageConstraintForeignKey	error = NewSystemError("05111")
	ErrStorageConstraintUnique 		error = NewSystemError("05112")
	ErrStorageNotFound         		error = NewSystemError("05120")
	// 08xxx: Command Line Interface Errors
	ErrCliGeneric 				error = NewSystemError("08000")
	ErrCliFileSystem 			error = NewSystemError("08100")
	ErrCliDirectoryOperation	error = NewSystemError("08101")
	ErrCliFileOperation			error = NewSystemError("08102")
	// 09xxx plugin errors.
	ErrPluginGeneric error = NewSystemError("09000")
)

// isErrorCodeDefined checks if the error code has been defined.
func isErrorCodeDefined(code string) bool {
	return errorCodes[code] != ""
}
