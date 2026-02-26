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
	// "modernc.org/sqlite"
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
	return errors.Join(fmt.Errorf("generic error (%s)", msg), err)
}
