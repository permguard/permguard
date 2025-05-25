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

// AuthorizationError represents the authorization error.
type AuthorizationError struct {
	code    string
	message string
}

// GetCode returns the code.
func (a *AuthorizationError) GetCode() string {
	return a.code
}

// GetMessage returns the message.
func (a *AuthorizationError) GetMessage() string {
	return a.message
}

// NewAuthorizationError creates a new authorization error.
func NewAuthorizationError(code string, message string) (*AuthorizationError, error) {
	return &AuthorizationError{
		code:    code,
		message: message,
	}, nil
}

// AuthorizationDecision represents the authorization decision.
type AuthorizationDecision struct {
	id         string
	decision   bool
	adminError *AuthorizationError
	userError  *AuthorizationError
}

// NewAuthorizationDecision creates a new authorization decision.
func NewAuthorizationDecision(id string, decision bool, adminError *AuthorizationError, userError *AuthorizationError) (*AuthorizationDecision, error) {
	return &AuthorizationDecision{
		id:         id,
		decision:   decision,
		adminError: adminError,
		userError:  userError,
	}, nil
}

// GetID returns the ID.
func (a *AuthorizationDecision) GetID() string {
	return a.id
}

// GetDecision returns the decision.
func (a *AuthorizationDecision) GetDecision() bool {
	return a.decision
}

// GetAdminError returns the admin error.
func (a *AuthorizationDecision) GetAdminError() *AuthorizationError {
	return a.adminError
}

// GetUserError returns the user error.
func (a *AuthorizationDecision) GetUserError() *AuthorizationError {
	return a.userError
}
