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
	// 00000 unknown error.
	"00000": "unknown error",
	// 001xx implementation errors.
	"00101": "invalid input parameter",
	// 01xxx configuration errors.
	"01000": "generic configuration error",
	// 04xxx client errors.
	"04000": "generic client error",
	"04100": "invalid entity",
	"04101": "invalid account id",
	"04102": "invalid id",
	"04103": "invalid uuid",
	"04104": "invalid name",
	// 05xxx server errors.
	"05000": "generic server error",
	"05001": "infrastractural error",
	"05100": "generic storage error",
	"05101": "duplicate entity",
	"05102": "not found",
	// 09xxx plugin errors.
	"09000": "generic plugin error",
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
	ErrUnknown        error = NewSystemError("00000")
	ErrNotImplemented error = NewSystemError("00001")
	// 01xxx configuration errors.
	ErrConfigurationGeneric error = NewSystemError("01000")
	// 04xxx client errors.
	ErrClientGeneric error = NewSystemError("04000")
	// 041xx client entity errors.
	ErrClientParameter  error = NewSystemError("04100")
	ErrClientPagination error = NewSystemError("01101")
	ErrClientEntity     error = NewSystemError("04111")
	ErrClientAccountID  error = NewSystemError("04112")
	ErrClientID         error = NewSystemError("04113")
	ErrClientUUID       error = NewSystemError("04114")
	ErrClientName       error = NewSystemError("04115")
	// 05xxx server errors.
	ErrServerGeneric        error = NewSystemError("05000")
	ErrServerInfrastructure error = NewSystemError("05001")
	ErrStorageGeneric       error = NewSystemError("05100")
	ErrStorageDuplicate     error = NewSystemError("05101")
	ErrStorageNotFound      error = NewSystemError("05102")
	// 09xxx plugin errors.
	ErrPluginGeneric error = NewSystemError("09000")
)

// isErrorCodeDefined checks if the error code has been defined.
func isErrorCodeDefined(code string) bool {
	return errorCodes[code] != ""
}
