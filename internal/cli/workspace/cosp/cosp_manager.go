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
	"strconv"

	"github.com/pelletier/go-toml"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// Hidden directories for states.
	hiddenStatesDir = "states"
	// Hidden directories for source code.
	hiddenSourceCodeDir = "@source"
	// Hidden directories for objects.
	hiddenObjectsDir = "objects"
	// Hidden directories for code.
	hiddenCodeDir = "code"
	// Hidden directories for plans.
	hiddenPlansDir = "plans"
	// Hidden configuration file.
	hiddenConfigFile = "config"
	// Hidden code map.
	hiddenCodeMap = "codemap"
	// Hidden code states.
	hiddenCodeState = "codestate"
)

// COSPManager implements the internal manager for code, objects, states and plans.
type COSPManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
	objMgr  *azlangobjs.ObjectManager
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

// getObjectsDir returns the objects directory.
func (m *COSPManager) getObjectsDir() string {
	return hiddenObjectsDir
}

// getStatesDir returns the states directory.
func (m *COSPManager) getStatesDir() string {
	return hiddenStatesDir
}

// getCodeDir returns the code directory.
func (m *COSPManager) getCodeDir() string {
	return hiddenCodeDir
}

// getCodeAreaDir returns the code area directory.
func (m *COSPManager) getCodeAreaDir() string {
	return filepath.Join(m.getCodeDir(), hiddenSourceCodeDir)
}

// getCodeAreaConfigFile returns the code area config file.
func (m *COSPManager) getCodeAreaConfigFile() string {
	return filepath.Join(m.getCodeAreaDir(), hiddenConfigFile)
}

// getStatesDir returns the code states directory.
func (m *COSPManager) getCodeStatesDir() string {
	return filepath.Join(m.getCodeDir(), hiddenStatesDir)
}

// getCodePlansDir returns the code plans directory.
func (m *COSPManager) getCodePlansDir() string {
	return filepath.Join(m.getCodeDir(), hiddenPlansDir)
}

// getCodeMapFile returns the code map file.
func (m *COSPManager) getCodeMapFile() string {
	return hiddenCodeMap
}

// getObjectDir returns the object directory.
func (m *COSPManager) getObjectDir(oid string, local bool) (string, string) {
	basePath := ""
	if local {
		basePath = m.getCodeAreaDir()
	}
	basePath = filepath.Join(basePath, m.getObjectsDir())
	folder := oid[:2]
	folder = filepath.Join(basePath, folder)
	m.persMgr.CreateDirIfNotExists(azicliwkspers.PermGuardDir, folder)
	name := oid[2:]
	return folder, name
}

// CleanCodeArea cleans the code area.
func (m *COSPManager) CleanCodeArea() (bool, error) {
	return m.persMgr.DeleteDir(azicliwkspers.PermGuardDir, m.getCodeAreaDir())
}

// SaveObject saves the object.
func (m *COSPManager) SaveObject(oid string, content []byte, isCodeDir bool) (bool, error) {
	folder, name := m.getObjectDir(oid, true)
	path := filepath.Join(folder, name)
	return m.persMgr.WriteBinaryFile(azicliwkspers.PermGuardDir, path, content, 0644, true)
}

// ReadObject reads the object.
func (m *COSPManager) ReadObject(oid string, idCodeDir bool) (*azlangobjs.Object, error) {
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

// SaveCodeAreaConfig saves the code area config.
func (m *COSPManager) SaveCodeAreaConfig(treeID, language string) error {
	config := &CodeLocalConfig{
		TreeID:   treeID,
		Language: language,
	}
	file := m.getCodeAreaConfigFile()
	return m.saveConfig(file, true, config)
}

// ReadCodeAreaConfig reads the code area config file.
func (m *COSPManager) ReadCodeAreaConfig() (*CodeLocalConfig, error) {
	var config CodeLocalConfig
	err := m.persMgr.ReadTOMLFile(azicliwkspers.PermGuardDir, m.getCodeAreaConfigFile(), &config)
	return &config, err
}

// SaveCodeMap saves the code map.
func (m *COSPManager) SaveCodeMap(codeFiles []CodeFile) error {
	path := filepath.Join(m.getCodeAreaDir(), hiddenCodeMap)
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

// ReadCodeMap reads the code map.
func (m *COSPManager) ReadCodeMap() ([]CodeFile, error) {
	path := filepath.Join(m.getCodeAreaDir(), hiddenCodeMap)
	var codeFiles []CodeFile
	recordFunc := func(record []string) error {
		if len(record) < 8 {
			return fmt.Errorf("invalid record format")
		}
		mode64, err := strconv.ParseUint(record[4], 10, 32)
		if err != nil {
			return err
		}
		mode := uint32(mode64)
		section, err := strconv.Atoi(record[5])
		if err != nil {
			return err
		}
		hasErrors, err := strconv.ParseBool(record[6])
		if err != nil {
			return err
		}
		codeFile := CodeFile{
			Path:         record[0],
			OID:          record[1],
			OType:        record[2],
			OName:        record[3],
			Mode:         mode,
			Section:      section,
			HasErrors:    hasErrors,
			ErrorMessage: record[7],
		}
		codeFiles = append(codeFiles, codeFile)
		return nil
	}
	err := m.persMgr.ReadFromCSVStream(azicliwkspers.PermGuardDir, path, nil, recordFunc)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to read code map")
	}

	return codeFiles, nil
}

// SaveCodeState saves the code state.
func (m *COSPManager) SaveCodeState(codeObjects []CodeObject) error {
	path := filepath.Join(m.getCodeAreaDir(), hiddenCodeState)
	rowFunc := func(record interface{}) []string {
		codeObject := record.(CodeObject)
		return []string{
			codeObject.OName,
			codeObject.OID,
		}
	}
	err := m.persMgr.WriteCSVStream(azicliwkspers.PermGuardDir, path, nil, codeObjects, rowFunc)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to write code state")
	}
	return nil
}

// ReadCodeState reads the code state.
func (m *COSPManager) ReadCodeState() ([]CodeObject, error) {
	path := filepath.Join(m.getCodeAreaDir(), hiddenCodeState)
	var codeObjects []CodeObject
	recordFunc := func(record []string) error {
		if len(record) < 2 {
			return fmt.Errorf("invalid record format")
		}
		codeObject := CodeObject{
			OName: record[0],
			OID:   record[1],
		}
		codeObjects = append(codeObjects, codeObject)
		return nil
	}
	err := m.persMgr.ReadFromCSVStream(azicliwkspers.PermGuardDir, path, nil, recordFunc)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to read code state")
	}
	return codeObjects, nil
}

// convertCodeFileToCodeObject converts the code file to the code object.
func (m *COSPManager) convertCodeFileToCodeObject(file CodeFile) (*CodeObject, error) {
	if file.OName == "" {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliRecordMalformed, "cli: code file name is empty.")
	}
	if file.OID == "" {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliRecordMalformed, "cli: code file OID is empty.")
	}
	return &CodeObject{
		OName: file.OName,
		OID: file.OID,
	}, nil
}

// ConvertCodeFilesToCodeObjects converts code files to code objects.
func (m *COSPManager) ConvertCodeFilesToCodeObjects(files []CodeFile) ([]CodeObject, error) {
	objects := make([]CodeObject, len(files))
	for i, file := range files {
		object, err := m.convertCodeFileToCodeObject(file)
		if err != nil {
			return nil, err
		}
		objects[i] = *object
	}
	return objects, nil
}

// CalculateCodeObjectsState calculates the code objects state.
func (m *COSPManager) CalculateCodeObjectsState(currentObjs []CodeObject, newObjs []CodeObject) []CodeObjectState {
	if currentObjs == nil {
		currentObjs = []CodeObject{}
	}
	if newObjs == nil {
		newObjs = []CodeObject{}
	}
	currentMap := make(map[string]string)
	newMap := make(map[string]string)
	for _, obj := range currentObjs {
		currentMap[obj.OName] = obj.OID
	}
	for _, obj := range newObjs {
		newMap[obj.OName] = obj.OID
	}
	result := []CodeObjectState{}
	for _, obj := range currentObjs {
		if newOID, exists := newMap[obj.OName]; exists {
			if obj.OID != newOID {
				result = append(result, CodeObjectState{CodeObject: obj, State: CodeObjectStateModify})
			}
		} else {
			result = append(result, CodeObjectState{CodeObject: obj, State: CodeObjectStateCreate})
		}
	}
	for _, obj := range newObjs {
		if _, exists := currentMap[obj.OName]; !exists {
			result = append(result, CodeObjectState{CodeObject: obj, State: CodeObjectStateDelete})
		}
	}
	return result
}
