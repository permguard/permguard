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

	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	WrapSqlite3ParamForeignKey = "foreign-key"
)

// WrapSqlite3Error wraps a sqlite3 error.
func WrapSqlite3Error(msg string, err error) error {
	return WrapSqlite3ErrorWithParams(msg, err, nil)
}

// readErroMapParam reads a parameter from a map.
func readErroMapParam(key string, params map[string]string) string {
	if params == nil {
		return ""
	}
	if value, ok := params[key]; ok {
		return value
	}
	return ""
}

func WrapSqlite3ErrorWithParams(msg string, err error, params map[string]string) error {
	sqliteErr, ok := err.(sqlite3.Error)
	if !ok {
		return azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageGeneric, fmt.Sprintf("storage: (%s)", msg))
	}
	switch sqliteErr.Code {
	case sqlite3.ErrConstraint:
		if errors.As(err, &sqliteErr) {
			if sqliteErr.ExtendedCode == sqlite3.ErrConstraintForeignKey {
				foreignKey := readErroMapParam(WrapSqlite3ParamForeignKey, params)
				if foreignKey != "" {
					return azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageConstraintForeignKey, fmt.Sprintf("storage: %s validation failed: the provided application id does not exist - %s", foreignKey, msg))
				}
				return azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageConstraintForeignKey, fmt.Sprintf("storage: foreign key constraint failed - %s", msg))
			}
			return azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageConstraintUnique, fmt.Sprintf("storage: unique constraint failed - %s", msg))
		}
		return azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageConstraintUnique, fmt.Sprintf("storage: constraint failed - %s", msg))
	case sqlite3.ErrNotFound:
		return azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageNotFound, fmt.Sprintf("storage: record not found - %s", msg))
	default:
		return azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageGeneric, fmt.Sprintf("storage: generic error (%s)", msg))
	}
}
