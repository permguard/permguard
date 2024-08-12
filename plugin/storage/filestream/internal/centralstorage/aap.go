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
	"fmt"

	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	azifsvolumes "github.com/permguard/permguard/plugin/storage/filestream/internal/volumes"
)

// FileStreamCentralStorageAAP implements the filestream central storage.
type FileStreamCentralStorageAAP struct {
	ctx          *azstorage.StorageContext
	volumeBinder azifsvolumes.FileStreamVolumeBinder
}

// newFileStreamAAPCentralStorage creates a new FileStreamAAPCentralStorage.
func newFileStreamAAPCentralStorage(storageContext *azstorage.StorageContext, volumeBinder azifsvolumes.FileStreamVolumeBinder) (*FileStreamCentralStorageAAP, error) {
	if storageContext == nil {
		return nil, fmt.Errorf("%q: %w", "storageContext is nil", azerrors.ErrInvalidInputParameter)
	}
	return &FileStreamCentralStorageAAP{
		ctx:          storageContext,
		volumeBinder: volumeBinder,
	}, nil
}
