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
	// 00000 unknown 01101error.
	"00000": "unknown error",
	// 001xx implementation errors.
	"00101": "not implemented",
	// 01xxx configuration errors.
	"01000": "generic configuration error",
	// 04xxx client errors.
	"04000": "generic client error",
	// 041xx client parameters errors.
	"04100": "invalid client parameter",
	"04101": "invalid pagination",
	// 041xx client entity errors.
	"04110": "invalid entity",
	"04111": "invalid id",
	"04112": "invalid uuid",
	"04113": "invalid name",
	// 05xxx server errors.
	"05000": "generic server error",
	"05001": "infrastractural error",
	"05100": "generic storage error",
	"05101": "storage entity mapping error",
	"05110": "storage constraint error",
	"05111": "storage constraint unique error",
	"05120": "storage not found error",
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
	ErrUnknown error = NewSystemError("00000")
	// 001xx implementation errors.
	ErrNotImplemented error = NewSystemError("00101")
	// 01xxx configuration errors.
	ErrConfigurationGeneric error = NewSystemError("01000")
	// 04xxx client errors.
	ErrClientGeneric error = NewSystemError("04000")
	// 041xx client parameters errors.
	ErrClientParameter  error = NewSystemError("04100")
	ErrClientPagination error = NewSystemError("04101")
	// 041xx client entity errors.
	ErrClientEntity error = NewSystemError("04110")
	ErrClientID     error = NewSystemError("04111")
	ErrClientUUID   error = NewSystemError("04112")
	ErrClientName   error = NewSystemError("04113")
	// 05xxx server errors.
	ErrServerGeneric           error = NewSystemError("05000")
	ErrServerInfrastructure    error = NewSystemError("05001")
	ErrStorageGeneric          error = NewSystemError("05100")
	ErrStorageEntityMapping    error = NewSystemError("05101")
	ErrStorageConstraint       error = NewSystemError("05110")
	ErrStorageConstraintUnique error = NewSystemError("05111")
	ErrStorageNotFound         error = NewSystemError("05120")
	// 09xxx plugin errors.
	ErrPluginGeneric error = NewSystemError("09000")
)

// isErrorCodeDefined checks if the error code has been defined.
func isErrorCodeDefined(code string) bool {
	return errorCodes[code] != ""
}
