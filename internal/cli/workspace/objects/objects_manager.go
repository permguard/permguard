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

package objects

import (
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
)

const (
	hiddenObjectsDir = "objects"
)

// ObjectsManager implements the internal manager for the objects file.
type ObjectsManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
}

// NewObjectsManager creates a new objectsuration manager.
func NewObjectsManager(ctx *aziclicommon.CliCommandContext, persMgr *azicliwkspers.PersistenceManager) *ObjectsManager {
	return &ObjectsManager{
		ctx:     ctx,
		persMgr: persMgr,
	}
}

// getObjectsDir returns the objects directory.
func (c *ObjectsManager) getObjectsDir() string {
	return hiddenObjectsDir
}
