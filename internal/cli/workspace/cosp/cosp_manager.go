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

package cosp

import (
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
)

const (
	// Hidden directories for code.
	hiddenCodeDir = "code"
	// Hidden directories for objects.
	hiddenObjectsDir = "objects"
	// Hidden directories for states.
	hiddenStatesDir  = "states"
	// Hidden directories for plans.
	hiddenPlansDir   = "plans"
)

// COSPManager implements the internal manager for code, objects, states and plans.
type COSPManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
}

// NewPlansManager creates a new plansuration manager.
func NewPlansManager(ctx *aziclicommon.CliCommandContext, persMgr *azicliwkspers.PersistenceManager) *COSPManager {
	return &COSPManager{
		ctx:     ctx,
		persMgr: persMgr,
	}
}

// getCodeDir returns the code directory.
func (c *COSPManager) getCodeDir() string {
	return hiddenCodeDir
}

// getObjectsDir returns the objects directory.
func (c *COSPManager) getObjectsDir() string {
	return hiddenObjectsDir
}

// getStatesDir returns the states directory.
func (c *COSPManager) getStatesDir() string {
	return hiddenStatesDir
}

// getPlansDir returns the plans directory.
func (c *COSPManager) getPlansDir() string {
	return hiddenPlansDir
}
