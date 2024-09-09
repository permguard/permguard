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
	"fmt"
	"path/filepath"

	"github.com/pelletier/go-toml"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// Hidden directories for code.
	hiddenCodeDir = "code"
	// Hidden directories for staging.
	hiddenStagingDir = "staging"
	// Hidden directories for objects.
	hiddenObjectsDir = "objects"
	// Hidden directories for states.
	hiddenStatesDir = "states"
	// Hidden directories for plans.
	hiddenPlansDir = "plans"
	// Hidden configuration file.
	hiddenConfiFile = "config"
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

// getStagingDir returns the staging directory.
func (c *COSPManager) getStagingDir() string {
	return hiddenStagingDir
}

// getStagingFile returns the staging config file.
func (c *COSPManager) getStagingFile() string {
	return filepath.Join(c.getCodeStagingDir(), hiddenConfiFile)
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

// getCodeStagingDir returns the code staging directory.
func (c *COSPManager) getCodeStagingDir() string {
	return filepath.Join(c.getCodeDir(), c.getStagingDir())
}

// getObjectDir returns the object directory.
func (c *COSPManager) getObjectDir(oid string, staging bool) (string, string) {
	basePath := ""
	if staging {
		basePath = c.getCodeStagingDir()
	}
	basePath = filepath.Join(basePath, c.getObjectsDir())
	folder := oid[:2]
	folder = filepath.Join(basePath, folder)
	c.persMgr.CreateDirIfNotExists(azicliwkspers.PermGuardDir, folder)
	name := oid[2:]
	return folder, name
}

// CleanStagingArea cleans the staging area.
func (c *COSPManager) CleanStagingArea() (bool, error) {
	return c.persMgr.DeleteDir(azicliwkspers.PermGuardDir, c.getCodeStagingDir())
}

// SaveObject saves the object.
func (c *COSPManager) SaveObject(oid string, content []byte, staging bool) (bool, error) {
	folder, name := c.getObjectDir(oid, true)
	path := filepath.Join(folder, name)
	return c.persMgr.WriteBinaryFile(azicliwkspers.PermGuardDir, path, content, 0644)
}

// saveConfig saves the configuration file.
func (m *COSPManager) saveConfig(name string, override bool, cfg any) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to marshal config")
	}
	if override {
		_, err = m.persMgr.WriteFile(azicliwkspers.PermGuardDir, name, data, 0644)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(azicliwkspers.PermGuardDir, name, data, 0644)
	}
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: failed to write config file %s", name))
	}
	return nil
}

// SaveCodeStagingConfig saves the code staging configuration.
func (m *COSPManager) SaveCodeStagingConfig(treeID, language string) error {
	config := &CodeStagingConfig{
		TreeID:   treeID,
		Language: language,
	}
	file := m.getStagingFile()
	return m.saveConfig(file, true, config)
}

// readCodeStagingConfig reads the configuration file.
func (m *COSPManager) readCodeStagingConfig() (*CodeStagingConfig, error) {
	var config CodeStagingConfig
	err := m.persMgr.ReadTOMLFile(azicliwkspers.PermGuardDir, m.getStagingFile(), &config)
	return &config, err
}
