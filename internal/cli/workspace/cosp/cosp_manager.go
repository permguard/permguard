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
	"strings"

	"github.com/pelletier/go-toml"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// Hidden directories for code.
	hiddenCodeDir = "code"
	// Hidden directories for source code.
	hiddenSourceCodeDir = "@source"
	// Hidden directories for objects.
	hiddenObjectsDir = "objects"
	// Hidden config file.
	hiddenConfigFile = "config"
	// Hidden code map file.
	hiddenCodeMapFile = "codemap"
	// Hidden code states file.
	hiddenCodeStateFile = "codestate"
	// Hidden code plan file.
	hiddenCodePlanFile = "plan"
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

// getCodeDir returns the code directory.
func (m *COSPManager) getCodeDir() string {
	return hiddenCodeDir
}

// getObjectsDir returns the objects directory.
func (m *COSPManager) getObjectsDir() string {
	return hiddenObjectsDir
}

// getCodeSourceDir returns the code source directory.
func (m *COSPManager) getCodeSourceDir() string {
	return filepath.Join(m.getCodeDir(), hiddenSourceCodeDir)
}

// getCodeSourceConfigFile returns the code source config file.
func (m *COSPManager) getCodeSourceConfigFile() string {
	return filepath.Join(m.getCodeSourceDir(), hiddenConfigFile)
}

// getCodeSourceObjectDir returns the code source object directory.
func (m *COSPManager) getCodeSourceObjectDir(oid string, basePath string) (string, string) {
	basePath = filepath.Join(basePath, m.getObjectsDir())
	folder := oid[:2]
	folder = filepath.Join(basePath, folder)
	m.persMgr.CreateDirIfNotExists(azicliwkspers.PermguardDir, folder)
	name := oid[2:]
	return folder, name
}

// CleanCodeSource cleans the code source area.
func (m *COSPManager) CleanCodeSource() (bool, error) {
	return m.persMgr.DeletePath(azicliwkspers.PermguardDir, m.getCodeSourceDir())
}

// SaveCodeSourceObject saves the object in the code source.
func (m *COSPManager) SaveCodeSourceObject(oid string, content []byte) (bool, error) {
	folder, name := m.getCodeSourceObjectDir(oid, m.getCodeSourceDir())
	path := filepath.Join(folder, name)
	return m.persMgr.WriteFile(azicliwkspers.PermguardDir, path, content, 0644, true)
}

// ReadCodeSourceObject reads the object from the code source.
func (m *COSPManager) ReadCodeSourceObject(oid string) (*azlangobjs.Object, error) {
	folder, name := m.getCodeSourceObjectDir(oid, m.getCodeSourceDir())
	path := filepath.Join(folder, name)
	data, _, err := m.persMgr.ReadFile(azicliwkspers.PermguardDir, path, true)
	if err != nil {
		return nil, err
	}
	return m.objMgr.CreateObjectFormData(data)
}

// saveConfig saves the config file.
func (m *COSPManager) saveConfig(name string, override bool, cfg any) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to marshal config")
	}
	if override {
		_, err = m.persMgr.WriteFile(azicliwkspers.PermguardDir, name, data, 0644, false)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(azicliwkspers.PermguardDir, name, data, 0644, false)
	}
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: failed to write config file %s", name))
	}
	return nil
}

// SaveCodeSourceConfig saves the code source config file.
func (m *COSPManager) SaveCodeSourceConfig(treeID, language string) error {
	config := &codeLocalConfig{
		Language: language,
		CodeState: codeStateConfig{
			TreeID: treeID,
		},
	}
	file := m.getCodeSourceConfigFile()
	return m.saveConfig(file, true, config)
}

// readCodeSourceConfig reads the code source config file.
func (m *COSPManager) readCodeSourceConfig() (*codeLocalConfig, error) {
	var config codeLocalConfig
	err := m.persMgr.ReadTOMLFile(azicliwkspers.PermguardDir, m.getCodeSourceConfigFile(), &config)
	return &config, err
}

// SaveCodeSourceCodeMap saves the code map in the code source.
func (m *COSPManager) SaveCodeSourceCodeMap(codeFiles []CodeFile) error {
	path := filepath.Join(m.getCodeSourceDir(), hiddenCodeMapFile)
	rowFunc := func(record any) []string {
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
	err := m.persMgr.WriteCSVStream(azicliwkspers.PermguardDir, path, nil, codeFiles, rowFunc, true)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to write code map")
	}
	return nil
}

// ReadCodeSourceCodeMap reads the code map from the code source.
func (m *COSPManager) ReadCodeSourceCodeMap() ([]CodeFile, error) {
	path := filepath.Join(m.getCodeSourceDir(), hiddenCodeMapFile)
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
	err := m.persMgr.ReadCSVStream(azicliwkspers.PermguardDir, path, nil, recordFunc, true)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to read code map")
	}

	return codeFiles, nil
}

// SaveCodeSourceCodeState saves the code object state in the code source.
func (m *COSPManager) SaveCodeSourceCodeState(codeObjects []CodeObjectState) error {
	path := filepath.Join(m.getCodeSourceDir(), hiddenCodeStateFile)
	return m.saveCodeObjectStates(path, codeObjects)
}

// ReadCodeSourceCodeState reads the code object state from the code source.
func (m *COSPManager) ReadCodeSourceCodeState() ([]CodeObjectState, error) {
	path := filepath.Join(m.getCodeSourceDir(), hiddenCodeStateFile)
	return m.readCodeObjectStates(path)
}

// SaveRemoteCodePlan saves the code plan for the input remote.
func (m *COSPManager) SaveRemoteCodePlan(remote string, refID string, codeObjects []CodeObjectState) error {
	path := filepath.Join(m.getCodeDir(), strings.ToLower(remote), strings.ToLower(refID))
	_, err := m.persMgr.CreateDirIfNotExists(azicliwkspers.PermguardDir, path)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to create code plan")
	}
	path = filepath.Join(path, hiddenCodePlanFile)
	return m.saveCodeObjectStates(path, codeObjects)
}

// ReadRemoteCodePlan reads the code plan from the input remote.
func (m *COSPManager) ReadRemoteCodePlan(remote string, refID string) ([]CodeObjectState, error) {
	path := filepath.Join(m.getCodeDir(), strings.ToLower(remote), strings.ToLower(refID), hiddenCodePlanFile)
	return m.readCodeObjectStates(path)
}

// convertCodeFileToCodeObjectState converts the code file to the code object.
func (m *COSPManager) convertCodeFileToCodeObjectState(codeFile CodeFile) (*CodeObjectState, error) {
	if codeFile.OName == "" {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliRecordMalformed, "cli: code file name is empty.")
	}
	if codeFile.OID == "" {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliRecordMalformed, "cli: code file OID is empty.")
	}
	return &CodeObjectState{
		CodeObject: CodeObject{
			OName: codeFile.OName,
			OType: codeFile.OType,
			OID:   codeFile.OID,
		},
	}, nil
}

// saveCodeObjectStates saves the code objects states.
func (m *COSPManager) saveCodeObjectStates(path string, codeObjects []CodeObjectState) error {
	rowFunc := func(record any) []string {
		codeObject := record.(CodeObjectState)
		return []string{
			codeObject.State,
			codeObject.OName,
			codeObject.OType,
			codeObject.OID,
		}
	}
	err := m.persMgr.WriteCSVStream(azicliwkspers.PermguardDir, path, nil, codeObjects, rowFunc, true)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to write code object state")
	}
	return nil
}

// readCodeObjectStates reads the code objects states.
func (m *COSPManager) readCodeObjectStates(path string) ([]CodeObjectState, error) {
	var codeObjects []CodeObjectState
	recordFunc := func(record []string) error {
		if len(record) < 2 {
			return fmt.Errorf("invalid record format")
		}
		codeObject := CodeObjectState{
			State: record[0],
			CodeObject: CodeObject{
				OName: record[1],
				OType: record[2],
				OID:   record[3],
			},
		}
		codeObjects = append(codeObjects, codeObject)
		return nil
	}
	err := m.persMgr.ReadCSVStream(azicliwkspers.PermguardDir, path, nil, recordFunc, true)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to read code state")
	}
	return codeObjects, nil
}

// ConvertCodeFilesToCodeObjectStates converts code files to code objects.
func (m *COSPManager) ConvertCodeFilesToCodeObjectStates(codeFiles []CodeFile) ([]CodeObjectState, error) {
	objects := make([]CodeObjectState, len(codeFiles))
	for i, file := range codeFiles {
		object, err := m.convertCodeFileToCodeObjectState(file)
		if err != nil {
			return nil, err
		}
		objects[i] = *object
	}
	return objects, nil
}

// CalculateCodeObjectsState calculates the code objects state.
func (m *COSPManager) CalculateCodeObjectsState(currentObjs []CodeObjectState, remoteObjs []CodeObjectState) []CodeObjectState {
	if currentObjs == nil {
		currentObjs = []CodeObjectState{}
	}
	if remoteObjs == nil {
		remoteObjs = []CodeObjectState{}
	}
	currentMap := make(map[string]string)
	for _, obj := range currentObjs {
		currentMap[obj.OName] = obj.OID
	}
	remoteMap := make(map[string]string)
	for _, obj := range remoteObjs {
		remoteMap[obj.OName] = obj.OID
	}
	result := []CodeObjectState{}
	for _, obj := range currentObjs {
		if newOID, exists := remoteMap[obj.OName]; exists {
			if obj.OID != newOID {
				result = append(result, CodeObjectState{CodeObject: obj.CodeObject, State: CodeObjectStateModify})
			} else {
				result = append(result, CodeObjectState{CodeObject: obj.CodeObject, State: CodeObjectStateUnchanged})
			}
		} else {
			result = append(result, CodeObjectState{CodeObject: obj.CodeObject, State: CodeObjectStateCreate})
		}
	}
	for _, obj := range remoteObjs {
		if _, exists := currentMap[obj.OName]; !exists {
			result = append(result, CodeObjectState{CodeObject: obj.CodeObject, State: CodeObjectStateDelete})
		}
	}
	return result
}

// ReadObject reads the object from the code source.
func (m *COSPManager) ReadObject(oid string) (*azlangobjs.Object, error) {
	folder, name := m.getCodeSourceObjectDir(oid, "")
	path := filepath.Join(folder, name)
	data, _, err := m.persMgr.ReadFile(azicliwkspers.PermguardDir, path, true)
	if err != nil {
		return nil, err
	}
	return m.objMgr.CreateObjectFormData(data)
}
