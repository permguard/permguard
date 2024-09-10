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

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
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
	// Hidden code map.
	hiddenCodeMap = "codemap"
)

// COSPManager implements the internal manager for code, objects, states and plans.
type COSPManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
	objMgr	*azlangobjs.ObjectManager
}

// NewPlansManager creates a new plansuration manager.
func NewPlansManager(ctx *aziclicommon.CliCommandContext, persMgr *azicliwkspers.PersistenceManager) (*COSPManager, error) {
	objMgr, err := azlangobjs.NewObjectManager()
	if err != nil {
		return nil, err
	}
	return &COSPManager{
		ctx:     ctx,
		persMgr: persMgr,
		objMgr:  objMgr,
	}, nil
}

// getCodeDir returns the code directory.
func (m *COSPManager) getCodeDir() string {
	return hiddenCodeDir
}

// getStagingDir returns the staging directory.
func (m *COSPManager) getStagingDir() string {
	return hiddenStagingDir
}

// getStagingFile returns the staging config file.
func (m *COSPManager) getStagingFile() string {
	return filepath.Join(m.getCodeStagingDir(), hiddenConfiFile)
}

// getObjectsDir returns the objects directory.
func (m *COSPManager) getObjectsDir() string {
	return hiddenObjectsDir
}

// getStatesDir returns the states directory.
func (m *COSPManager) getStatesDir() string {
	return hiddenStatesDir
}

// getPlansDir returns the plans directory.
func (m *COSPManager) getPlansDir() string {
	return hiddenPlansDir
}

// getCodeStagingDir returns the code staging directory.
func (m *COSPManager) getCodeStagingDir() string {
	return filepath.Join(m.getCodeDir(), m.getStagingDir())
}

// getCodeMap returns the code map.
func (m *COSPManager) getCodeMap() string {
	return hiddenCodeMap
}

// getObjectDir returns the object directory.
func (m *COSPManager) getObjectDir(oid string, staging bool) (string, string) {
	basePath := ""
	if staging {
		basePath = m.getCodeStagingDir()
	}
	basePath = filepath.Join(basePath, m.getObjectsDir())
	folder := oid[:2]
	folder = filepath.Join(basePath, folder)
	m.persMgr.CreateDirIfNotExists(azicliwkspers.PermGuardDir, folder)
	name := oid[2:]
	return folder, name
}

// CleanStagingArea cleans the staging area.
func (m *COSPManager) CleanStagingArea() (bool, error) {
	return m.persMgr.DeleteDir(azicliwkspers.PermGuardDir, m.getCodeStagingDir())
}

// SaveObject saves the object.
func (m *COSPManager) SaveObject(oid string, content []byte, staging bool) (bool, error) {
	folder, name := m.getObjectDir(oid, true)
	path := filepath.Join(folder, name)
	return m.persMgr.WriteBinaryFile(azicliwkspers.PermGuardDir, path, content, 0644, true)
}

// ReadObject reads the object.
func (m *COSPManager) ReadObject(oid string, staging bool) (*azlangobjs.Object, error) {
	folder, name := m.getObjectDir(oid, true)
	path := filepath.Join(folder, name)
	data, _, err := m.persMgr.ReadFile(azicliwkspers.PermGuardDir, path, true)
	if err != nil {
		return nil, err
	}
	return m.objMgr.ReadObjectFormData(data)
}

// saveConfig saves the configuration file.
func (m *COSPManager) saveConfig(name string, override bool, cfg any) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to marshal config")
	}
	if override {
		_, err = m.persMgr.WriteFile(azicliwkspers.PermGuardDir, name, data, 0644, false)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(azicliwkspers.PermGuardDir, name, data, 0644, false)
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

// ReadCodeStagingConfig reads the configuration file.
func (m *COSPManager) ReadCodeStagingConfig() (*CodeStagingConfig, error) {
	var config CodeStagingConfig
	err := m.persMgr.ReadTOMLFile(azicliwkspers.PermGuardDir, m.getStagingFile(), &config)
	return &config, err
}

// SaveCodeMap saves the code map.
func (m *COSPManager) SaveCodeMap(codeFiles []CodeFile) error {
	path := filepath.Join(m.getCodeStagingDir(), "codemap")
	rowFunc := func(record interface{}) []string {
		codeFile := record.(CodeFile)
		return []string{
			codeFile.Path,
			codeFile.OID,
			codeFile.OType,
			codeFile.OName,
			fmt.Sprintf("%d", codeFile.Mode),
			fmt.Sprintf("%d", codeFile.Section),
			fmt.Sprintf("%v", codeFile.HasErrors),
			codeFile.ErrorMessage,
		}
	}
	err := m.persMgr.WriteCSVStream(azicliwkspers.PermGuardDir, path, nil, codeFiles, rowFunc)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to write code map")
	}
	return nil
}
