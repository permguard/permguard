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
	"errors"
	"fmt"

	"github.com/mattn/go-sqlite3"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

// WrapSqlite3Error wraps a sqlite3 error.
func WrapSqlite3Error(msg string, err error) error {
	sqliteErr, ok := err.(sqlite3.Error)
	if !ok {
		return azerrors.WrapSystemError(azerrors.ErrStorageGeneric, fmt.Sprintf("storage: (%s)", msg))
	}
	switch sqliteErr.Code {
	case sqlite3.ErrConstraint:
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return azerrors.WrapSystemError(azerrors.ErrStorageConstraintUnique, fmt.Sprintf("storage: unique constraint failed - %s", msg))
		}
		return azerrors.WrapSystemError(azerrors.ErrStorageConstraintUnique, fmt.Sprintf("storage: constraint failed - %s", msg))
	case sqlite3.ErrNotFound:
		return azerrors.WrapSystemError(azerrors.ErrStorageNotFound, fmt.Sprintf("storage: record not found - %s", msg))
	default:
		return azerrors.WrapSystemError(azerrors.ErrStorageGeneric, fmt.Sprintf("storage: generic error (%s)", msg))
	}
}
