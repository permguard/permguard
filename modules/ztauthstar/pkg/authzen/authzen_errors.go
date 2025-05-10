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

package authzen

const (
	// AuthzErrBadRequestCode is the error code for bad request.
	AuthzErrBadRequestCode = "400"
	// AuthzErrBadRequestMessage is the error message for bad request.
	AuthzErrBadRequestMessage = "Bad Request"

	// AuthzErrUnauthorizedCode is the error code for unauthorized.
	AuthzErrUnauthorizedCode = "401"
	// AuthzErrUnauthorizedMessage is the error message for unauthorized.
	AuthzErrUnauthorizedMessage = "Unauthorized"

	// AuthzErrForbiddenCode is the error code for forbidden.
	AuthzErrForbiddenCode = "403"
	// AuthzErrForbiddenMessage is the error message for forbidden.
	AuthzErrForbiddenMessage = "Forbidden"

	// AuthzErrInternalErrorCode is the error code for internal server error.
	AuthzErrInternalErrorCode = "500"
	// AuthzErrInternalErrorMessage is the error message for internal server error.
	AuthzErrInternalErrorMessage = "Internal Server Error"
)
