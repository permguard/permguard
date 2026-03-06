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

package storage

import "errors"

// Sentinel errors for storage operations.
// Callers can use errors.Is() to check for specific error conditions.
var (
	// ErrNotFound indicates the requested resource does not exist.
	ErrNotFound = errors.New("storage: resource not found")

	// ErrAlreadyExists indicates a resource with the same identity already exists.
	ErrAlreadyExists = errors.New("storage: resource already exists")

	// ErrConflict indicates a conflict such as an optimistic-lock violation.
	ErrConflict = errors.New("storage: conflict")

	// ErrInvalidInput indicates the caller provided invalid data.
	ErrInvalidInput = errors.New("storage: invalid input")

	// ErrInternal indicates an unexpected internal storage error.
	ErrInternal = errors.New("storage: internal error")
)
