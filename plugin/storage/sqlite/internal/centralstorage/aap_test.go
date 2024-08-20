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

package centralstorage
import (
	"testing"

	"github.com/stretchr/testify/assert"

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

// TestNewSQLiteAAPCentralStorage tests the newSQLiteAAPCentralStorage function.
func TestNewSQLiteAAPCentralStorage(t *testing.T) {
	assert := assert.New(t)
	storage, err := newSQLiteAAPCentralStorage(nil, nil, nil, nil)
	assert.Nil(storage, "storage should be nil")
	assert.NotNil(err, "error should not be nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
}
