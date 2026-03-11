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

package repositories

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
)

// SQLite error wrapping constants.
const (
	WrapSqliteParamForeignKey = "foreign-key"
)

// WrapSqliteError wraps a sqlite error.
func WrapSqliteError(msg string, err error) error {
	return WrapSqliteErrorWithParams(msg, err, nil)
}

// WrapSqliteErrorWithParams wraps a sqlite error with parameters.
func WrapSqliteErrorWithParams(msg string, err error, _ map[string]string) error {
	if err == nil {
		return fmt.Errorf("storage: %s: %w", msg, azstorage.ErrInternal)
	}

	sentinel := classifyError(err)
	return fmt.Errorf("storage: %s: %w: %w", msg, sentinel, err)
}

// classifyError maps a raw error to the appropriate sentinel error.
func classifyError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return azstorage.ErrNotFound
	}

	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "UNIQUE constraint"):
		return azstorage.ErrAlreadyExists
	case strings.Contains(errMsg, "FOREIGN KEY constraint"):
		return azstorage.ErrConflict
	case strings.Contains(errMsg, "NOT NULL constraint"):
		return azstorage.ErrInvalidInput
	default:
		return azstorage.ErrInternal
	}
}
