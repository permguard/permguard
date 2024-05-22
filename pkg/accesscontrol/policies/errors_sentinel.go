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

package policies

import "errors"

var (
	// ErrPoliciesUnsupportedDataType is returned wether the data type is not supported.
	ErrPoliciesUnsupportedDataType = errors.New("policy: unsupported data type")
	// ErrPoliciesInvalidDataType is returned wether the data type is invalid.
	ErrPoliciesInvalidDataType = errors.New("policy: invalid data type")
	// ErrPoliciesUnsupportedSyntax is returned wether the string implement an unsupported syntax.
	ErrPoliciesUnsupportedSyntax = errors.New("policy: unsupported syntax")
	// ErrPoliciesInvalidUUR is returned wether the action string is invalid or unsupported.
	ErrPoliciesInvalidUUR = errors.New("policy: invalid UUR")
	// ErrPoliciesInvalidAction is returned wether the action string is invalid or unsupported.
	ErrPoliciesInvalidAction = errors.New("policy: invalid action")
	// ErrPoliciesUnsupportedVersion is returned wether required version is not supported.
	ErrPoliciesUnsupportedVersion = errors.New("policy: unsupported version")
	// ErrPoliciesJSONSchemaValidation is returned wether the json schema validation failed.
	ErrPoliciesJSONSchemaValidation = errors.New("policy: JSON schema validation error")
)
