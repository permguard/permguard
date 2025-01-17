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
	"testing"

	"github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"

	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

func TestWrapSqlite3Error(t *testing.T) {
	tests := map[string]struct {
		ErrorIn  error
		ErrorOut error
	}{
		"here a sample error 1": {
			errors.New("here a sample error 1"),
			azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageConstraintUnique, "storage: constraint failed - here a sample error 1"),
		},
		"here a sample error 2": {
			sqlite3.Error{Code: sqlite3.ErrConstraint},
			azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageConstraintUnique, "storage: constraint failed - here a sample error 2"),
		},
		"here a sample error 3": {
			sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique},
			azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageConstraintUnique, "storage: unique constraint failed - here a sample error 3"),
		},
		"here a sample error 4": {
			sqlite3.Error{Code: sqlite3.ErrNotFound},
			azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageNotFound, "storage: record not found - here a sample error 4"),
		},
		"here a sample error 5": {
			sqlite3.Error{Code: sqlite3.ErrAuth},
			azerrors.WrapSystemErrorWithMessage(azerrors.ErrStorageGeneric, "storage: generic error (here a sample error 5)"),
		},
	}
	for message, test := range tests {
		t.Run(message, func(t *testing.T) {
			err := WrapSqlite3Error(message, test.ErrorIn)
			assert.Error(t, err)
			assert.NotNil(t, azerrors.ConvertToSystemError(test.ErrorOut))
		})
	}
}
