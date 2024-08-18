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
	"fmt"

	"github.com/mattn/go-sqlite3"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

// WrapSqlStorageError wraps the sql error with a storage error.
func WrapSqlStorageError(msg string, err error) error {
	errMsg := fmt.Sprintf("storage: %s", msg)
	sqliteErr, ok := err.(sqlite3.Error)
	if !ok {
		return azerrors.WrapSystemError(azerrors.ErrStorageGeneric, errMsg)
	}
	switch sqliteErr.Code {
	case sqlite3.ErrConstraint:
		return err
	case sqlite3.ErrNotFound:
		return err
	default:
		return azerrors.WrapSystemError(azerrors.ErrStorageGeneric, errMsg)
	}
}
