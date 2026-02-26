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

package pdp

import (
	"strings"
)

const (
	// Permguard is the permguard constant.
	Permguard = "PERMGUARD"
	// PermguardUser is the permguard user constant.
	PermguardUser = "USER"
	// PermguardWorkload is the permguard workload constant.
	PermguardWorkload = "WORKLOAD"
	// PermguardAttribute is the permguard attribute constant.
	PermguardAttribute = "ATTRIBUTE"
)

// IsValidKey checks if the key is valid.
func IsValidKey(key string) bool {
	key = strings.ToUpper(strings.ReplaceAll(key, " ", ""))
	return key != Permguard
}

// IsValidProperties checks if the properties are valid.
func IsValidProperties(properties map[string]any) bool {
	for key := range properties {
		if !IsValidKey(key) {
			return false
		}
	}
	return true
}

// IsValidIdentiyType checks if the identity type is valid.
func IsValidIdentiyType(identityType string) bool {
	identityType = strings.ToUpper(identityType)
	switch identityType {
	case PermguardUser, PermguardWorkload, PermguardAttribute:
		return true
	}
	return false
}

// NewEvaluationErrorResponse creates an evaluation error response.
func NewEvaluationErrorResponse(requestID string, erroCode string, adminReason string, userReason string) *EvaluationResponse {
	return &EvaluationResponse{
		RequestID: requestID,
		Decision:  false,
		Context: &ContextResponse{
			ReasonAdmin: &ReasonResponse{
				Code:    erroCode,
				Message: adminReason,
			},
			ReasonUser: &ReasonResponse{
				Code:    erroCode,
				Message: userReason,
			},
		},
	}
}

// NewAuthorizationCheckErrorResponse creates an authorization check error response.
func NewAuthorizationCheckErrorResponse(authzCheckResponse *AuthorizationCheckResponse, requestID string, erroCode string, adminReason string, userReason string) *AuthorizationCheckResponse {
	if authzCheckResponse == nil {
		authzCheckResponse = &AuthorizationCheckResponse{}
	}
	if len(requestID) > 0 {
		authzCheckResponse.RequestID = requestID
	}
	if authzCheckResponse.Context == nil {
		authzCheckResponse.Context = &ContextResponse{}
	}
	authzCheckResponse.Context.ReasonAdmin = &ReasonResponse{
		Code:    erroCode,
		Message: adminReason,
	}
	authzCheckResponse.Context.ReasonUser = &ReasonResponse{
		Code:    erroCode,
		Message: userReason,
	}
	return authzCheckResponse
}
