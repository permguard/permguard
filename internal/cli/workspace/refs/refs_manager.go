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

package refs

import (
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
)

const (
	hiddenRefsDir	= "refs"
	hiddenHeadFile	= "HEAD"
)

// RefsManager implements the internal manager for the refs file.
type RefsManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
}

// NewRefsManager creates a new refsuration manager.
func NewRefsManager(ctx *aziclicommon.CliCommandContext, persMgr *azicliwkspers.PersistenceManager) *RefsManager {
	return &RefsManager{
		ctx:     ctx,
		persMgr: persMgr,
	}
}

// GetRefsDir returns the refs directory.
func (c *RefsManager) GetRefsDir() string {
	return hiddenRefsDir
}

// GetHeadFile returns the head file.
func (c *RefsManager) GetHeadFile() string {
	return hiddenHeadFile
}

// Iniitalize the refs resources.
func (c *RefsManager) Iniitalize() error {
	_, err := c.persMgr.CreateDirIfNotExists(true, c.GetRefsDir())
	if err != nil {
		return err
	}
	headFile := c.GetHeadFile()
	_, err = c.persMgr.CreateFileIfNotExists(true, headFile)
	if err != nil {
		return err
	}
	return nil
}
