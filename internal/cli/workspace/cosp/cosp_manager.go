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
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml"

	"github.com/permguard/permguard/internal/cli/common"
	wkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/internal/cli/workspace/persistence"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

const (
	// Hidden directories for code.
	hiddenCodeDir = "code"
	// Hidden directories for source code.
	hiddenSourceCodeDir = "@workspace"
	// Hidden directories for objs.
	hiddenObjectsDir = "objs"
	// Hidden config file.
	hiddenConfigFile = "config"
	// Hidden code map file.
	hiddenCodeMapFile = "codemap"
	// Hidden code states file.
	hiddenCodeStateFile = "codestate"
	// Hidden code plan file.
	hiddenCodePlanFile = "plan"
)

// COSPManager implements the internal manager for code, objs, states and plans.
type COSPManager struct {
	ctx     *common.CliCommandContext
	persMgr *persistence.PersistenceManager
	objMgr  *objects.ObjectManager
}

// NewPlansManager creates a new plansuration manager.
func NewPlansManager(ctx *common.CliCommandContext, persMgr *persistence.PersistenceManager) (*COSPManager, error) {
	objMgr, err := objects.NewObjectManager()
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

// getObjectsDir returns the objs directory.
func (m *COSPManager) getObjectsDir() string {
	return hiddenObjectsDir
}

// getCodeSourceDir returns the code source directory.
func (m *COSPManager) getCodeSourceDir() string {
	return filepath.Join(m.getCodeDir(), hiddenSourceCodeDir)
}

// getCodeSourceObjectsDir returns the code source objs directory.
func (m *COSPManager) getCodeSourceObjectsDir() string {
	return filepath.Join(m.getCodeSourceDir(), m.getObjectsDir())
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
	name := oid[2:]
	return folder, name
}

// CleanCodeSource cleans the code source area.
func (m *COSPManager) CleanCodeSource() (bool, error) {
	return m.persMgr.DeletePath(persistence.PermguardDir, m.getCodeSourceDir())
}

// SaveCodeSourceObject saves the object in the code source.
func (m *COSPManager) SaveCodeSourceObject(oid string, content []byte) (bool, error) {
	folder, name := m.getCodeSourceObjectDir(oid, m.getCodeSourceDir())
	path := filepath.Join(folder, name)
	_, err := m.persMgr.CreateDirIfNotExists(persistence.PermguardDir, folder)
	if err != nil {
		return false, errors.Join(err, fmt.Errorf("cli: failed to save object %s", oid))
	}
	return m.persMgr.WriteFile(persistence.PermguardDir, path, content, 0644, true)
}

// ReadCodeSourceObject reads the object from the code source.
func (m *COSPManager) ReadCodeSourceObject(oid string) (*objects.Object, error) {
	folder, name := m.getCodeSourceObjectDir(oid, m.getCodeSourceDir())
	path := filepath.Join(folder, name)
	data, _, err := m.persMgr.ReadFile(persistence.PermguardDir, path, true)
	if err != nil {
		return nil, err
	}
	return m.objMgr.DeserializeObjectFromBytes(data)
}

// saveConfig saves the config file.
func (m *COSPManager) saveConfig(name string, override bool, cfg any) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return errors.Join(err, errors.New("cli: failed to marshal config"))
	}
	if override {
		_, err = m.persMgr.WriteFile(persistence.PermguardDir, name, data, 0644, false)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(persistence.PermguardDir, name, data, 0644, false)
	}
	if err != nil {
		return fmt.Errorf("cli: failed to write config file %s", name)
	}
	return nil
}

// SaveCodeSourceConfig saves the code source config file.
func (m *COSPManager) SaveCodeSourceConfig(treeID string) error {
	config := &codeLocalConfig{
		CodeState: codeStateConfig{
			TreeID: treeID,
		},
	}
	file := m.getCodeSourceConfigFile()
	return m.saveConfig(file, true, config)
}

// SaveCodeSourceCodeMap saves the code map in the code source.
func (m *COSPManager) SaveCodeSourceCodeMap(codeFiles []CodeFile) error {
	_, err := m.persMgr.CreateDirIfNotExists(persistence.PermguardDir, m.getCodeSourceDir())
	if err != nil {
		return errors.Join(err, errors.New("cli: failed to create code plan"))
	}
	path := filepath.Join(m.getCodeSourceDir(), hiddenCodeMapFile)
	rowFunc := func(record any) []string {
		codeFile := record.(CodeFile)
		return []string{
			codeFile.Path,
			codeFile.OID,
			codeFile.OType,
			codeFile.OName,
			codeFile.CodeID,
			codeFile.CodeType,
			codeFile.Language,
			codeFile.LanguageVersion,
			codeFile.LanguageType,
			fmt.Sprintf("%d", codeFile.Mode),
			fmt.Sprintf("%d", codeFile.Section),
			fmt.Sprintf("%v", codeFile.HasErrors),
			codeFile.ErrorMessage,
		}
	}
	err = m.persMgr.WriteCSVStream(persistence.PermguardDir, path, nil, codeFiles, rowFunc, true)
	if err != nil {
		return errors.Join(err, errors.New("cli: failed to write code map"))
	}
	return nil
}

// ReadCodeSourceCodeMap reads the code map from the code source.
func (m *COSPManager) ReadCodeSourceCodeMap() ([]CodeFile, error) {
	path := filepath.Join(m.getCodeSourceDir(), hiddenCodeMapFile)
	var codeFiles []CodeFile
	recordFunc := func(record []string) error {
		if len(record) < 12 {
			return fmt.Errorf("invalid record format")
		}
		mode64, err := strconv.ParseUint(record[9], 10, 32)
		if err != nil {
			return err
		}
		mode := uint32(mode64)
		section, err := strconv.Atoi(record[10])
		if err != nil {
			return err
		}
		hasErrors, err := strconv.ParseBool(record[11])
		if err != nil {
			return err
		}
		codeFile := CodeFile{
			Path:            record[0],
			OID:             record[1],
			OType:           record[2],
			OName:           record[3],
			CodeID:          record[4],
			CodeType:        record[5],
			Language:        record[6],
			LanguageVersion: record[7],
			LanguageType:    record[8],
			Mode:            mode,
			Section:         section,
			HasErrors:       hasErrors,
			ErrorMessage:    record[12],
		}
		codeFiles = append(codeFiles, codeFile)
		return nil
	}
	err := m.persMgr.ReadCSVStream(persistence.PermguardDir, path, nil, recordFunc, true)
	if err != nil {
		return nil, errors.Join(err, errors.New("cli: failed to read code map"))
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

// BuildCodeSourceCodeStateForTree builds the code object state for the input tree.
func (m *COSPManager) BuildCodeSourceCodeStateForTree(tree *objects.Tree) ([]CodeObjectState, error) {
	if tree == nil {
		return nil, errors.New("cli: tree is nil")
	}
	codeObjectStates := []CodeObjectState{}
	for _, entry := range tree.GetEntries() {
		codeObjState := CodeObjectState{
			CodeObject: CodeObject{
				Partition:       entry.GetPartition(),
				OName:           entry.GetOName(),
				OType:           entry.GetType(),
				OID:             entry.GetOID(),
				CodeID:          entry.GetCodeID(),
				CodeType:        entry.GetCodeType(),
				Language:        entry.GetLanguage(),
				LanguageType:    entry.GetLanguageType(),
				LanguageVersion: entry.GetLanguageVersion(),
			},
			State: "",
		}
		codeObjectStates = append(codeObjectStates, codeObjState)
	}
	return codeObjectStates, nil
}

// SaveRemoteCodePlan saves the code plan for the input remote.
func (m *COSPManager) SaveRemoteCodePlan(ref string, codeObjects []CodeObjectState) error {
	path := filepath.Join(m.getCodeDir(), strings.ToLower(ref))
	_, err := m.persMgr.CreateDirIfNotExists(persistence.PermguardDir, path)
	if err != nil {
		return errors.Join(err, errors.New("cli: failed to create code plan"))
	}
	path = filepath.Join(path, hiddenCodePlanFile)
	return m.saveCodeObjectStates(path, codeObjects)
}

// ReadRemoteCodePlan reads the code plan from the input remote.
func (m *COSPManager) ReadRemoteCodePlan(ref string) ([]CodeObjectState, error) {
	path := filepath.Join(m.getCodeDir(), strings.ToLower(ref), hiddenCodePlanFile)
	return m.readCodeObjectStates(path)
}

// CleanCode cleans the code.
func (m *COSPManager) CleanCode(ref string) (bool, error) {
	path := filepath.Join(m.getCodeDir(), strings.ToLower(ref))
	return m.persMgr.DeletePath(persistence.PermguardDir, path)
}

// convertCodeFileToCodeObjectState converts the code file to the code object.
func (m *COSPManager) convertCodeFileToCodeObjectState(codeFile CodeFile) (*CodeObjectState, error) {
	if codeFile.OName == "" {
		return nil, errors.New("cli: code file name is empty")
	}
	if codeFile.OID == "" {
		return nil, errors.New("cli: code file OID is empty")
	}
	if codeFile.CodeID == "" {
		return nil, errors.New("cli: code file CodeID is empty")
	}
	if codeFile.CodeType == "" {
		return nil, errors.New("cli: code file CodeType is empty")
	}
	if codeFile.Language == "" {
		return nil, errors.New("cli: code file Language is empty")
	}
	if codeFile.LanguageVersion == "" {
		return nil, errors.New("cli: code file LanguageVersion is empty")
	}
	if codeFile.LanguageType == "" {
		return nil, errors.New("cli: code file LanguageType is empty")
	}
	return &CodeObjectState{
		CodeObject: CodeObject{
			Partition:       codeFile.Partition,
			OName:           codeFile.OName,
			OType:           codeFile.OType,
			OID:             codeFile.OID,
			CodeID:          codeFile.CodeID,
			CodeType:        codeFile.CodeType,
			Language:        codeFile.Language,
			LanguageVersion: codeFile.LanguageVersion,
			LanguageType:    codeFile.LanguageType,
		},
	}, nil
}

// saveCodeObjectStates saves the code objs states.
func (m *COSPManager) saveCodeObjectStates(path string, codeObjects []CodeObjectState) error {
	rowFunc := func(record any) []string {
		codeObject := record.(CodeObjectState)
		return []string{
			codeObject.State,
			codeObject.Partition,
			codeObject.OName,
			codeObject.OType,
			codeObject.OID,
			codeObject.CodeID,
			codeObject.CodeType,
			codeObject.Language,
			codeObject.LanguageVersion,
			codeObject.LanguageType,
		}
	}
	err := m.persMgr.WriteCSVStream(persistence.PermguardDir, path, nil, codeObjects, rowFunc, true)
	if err != nil {
		return errors.Join(err, errors.New("cli: failed to write code object state"))
	}
	return nil
}

// readCodeObjectStates reads the code objs states.
func (m *COSPManager) readCodeObjectStates(path string) ([]CodeObjectState, error) {
	var codeObjects []CodeObjectState
	recordFunc := func(record []string) error {
		if len(record) < 2 {
			return fmt.Errorf("invalid record format")
		}
		codeObject := CodeObjectState{
			State: record[0],
			CodeObject: CodeObject{
				Partition:       record[1],
				OName:           record[2],
				OType:           record[3],
				OID:             record[4],
				CodeID:          record[5],
				CodeType:        record[6],
				Language:        record[7],
				LanguageVersion: record[8],
				LanguageType:    record[9],
			},
		}
		codeObjects = append(codeObjects, codeObject)
		return nil
	}
	err := m.persMgr.ReadCSVStream(persistence.PermguardDir, path, nil, recordFunc, true)
	if err != nil {
		return nil, errors.Join(err, errors.New("cli: failed to read code state"))
	}
	return codeObjects, nil
}

// ConvertCodeFilesToCodeObjectStates converts code files to code objs.
func (m *COSPManager) ConvertCodeFilesToCodeObjectStates(codeFiles []CodeFile) ([]CodeObjectState, error) {
	objs := make([]CodeObjectState, len(codeFiles))
	for i, file := range codeFiles {
		object, err := m.convertCodeFileToCodeObjectState(file)
		if err != nil {
			return nil, err
		}
		objs[i] = *object
	}
	return objs, nil
}

// CalculateCodeObjectsState calculates the code objs state.
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

// SaveObject saves the object in the object store.
func (m *COSPManager) SaveObject(oid string, content []byte) (bool, error) {
	folder, name := m.getCodeSourceObjectDir(oid, "")
	path := filepath.Join(folder, name)
	_, err := m.persMgr.CreateDirIfNotExists(persistence.PermguardDir, folder)
	if err != nil {
		return false, errors.Join(err, fmt.Errorf("cli: failed to save object %s", oid))
	}
	return m.persMgr.WriteFile(persistence.PermguardDir, path, content, 0644, true)
}

// ReadObject reads the object from the objs store.
func (m *COSPManager) ReadObject(oid string) (*objects.Object, error) {
	folder, name := m.getCodeSourceObjectDir(oid, "")
	path := filepath.Join(folder, name)
	data, _, err := m.persMgr.ReadFile(persistence.PermguardDir, path, true)
	if err != nil {
		return nil, err
	}
	return m.objMgr.DeserializeObjectFromBytes(data)
}

// GetObjects returns the objs.
func (m *COSPManager) getObjects(path string, isStore bool) ([]objects.Object, error) {
	objs := []objects.Object{}
	dirs, err := m.persMgr.ListDirectories(persistence.PermguardDir, path)
	if err != nil {
		return nil, err
	}
	for _, dir := range dirs {
		files, err := m.persMgr.ListFiles(persistence.PermguardDir, filepath.Join(path, dir))
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			oid := fmt.Sprintf("%s%s", dir, file)
			var obj *objects.Object
			if isStore {
				obj, err = m.ReadObject(oid)
				if err != nil {
					return nil, err
				}
			} else {
				obj, err = m.ReadCodeSourceObject(oid)
				if err != nil {
					return nil, err
				}
			}
			objs = append(objs, *obj)
		}
	}
	return objs, nil
}

// GetObjects returns the objs.
func (m *COSPManager) GetObjects(includeStorage, includeCode bool) ([]objects.Object, error) {
	objs := []objects.Object{}
	if includeCode {
		if ok, _ := m.persMgr.CheckPathIfExists(persistence.PermguardDir, m.getCodeSourceObjectsDir()); ok {
			codeObjs, err := m.getObjects(m.getCodeSourceObjectsDir(), false)
			if err != nil {
				return nil, err
			}
			objs = append(objs, codeObjs...)
		}
	}
	if includeStorage {
		if ok, _ := m.persMgr.CheckPathIfExists(persistence.PermguardDir, m.getObjectsDir()); ok {
			storageObjs, err := m.getObjects(m.getObjectsDir(), true)
			if err != nil {
				return nil, err
			}
			objs = append(objs, storageObjs...)
		}
	}
	return objs, nil
}

// GetCommit gets the commit.
func (m *COSPManager) GetCommit(commitID string) (*objects.Commit, error) {
	obj, err := m.ReadObject(commitID)
	if err != nil {
		return nil, err
	}
	objInfo, err := m.objMgr.GetObjectInfo(obj)
	if err != nil {
		return nil, err
	}
	if objInfo.GetType() != objects.ObjectTypeCommit {
		return nil, fmt.Errorf("cli: oid %s is not a valid commit", commitID)
	}
	commit := objInfo.GetInstance().(*objects.Commit)
	return commit, nil
}

// GetHistory gets the commit history.
func (m *COSPManager) GetHistory(commitID string) ([]wkscommon.CommitInfo, error) {
	var commits []wkscommon.CommitInfo
	commit, err := m.GetCommit(commitID)
	if err != nil {
		return nil, err
	}

	for commit != nil {
		commitInfo, err := wkscommon.NewCommitInfo(commitID, commit)
		if err != nil {
			return nil, err
		}
		commits = append(commits, *commitInfo)
		parentID := commit.GetParent()
		if parentID == objects.ZeroOID {
			break
		}
		commit, err = m.GetCommit(parentID)
		if err != nil {
			return nil, err
		}
		commitID = parentID
	}
	return commits, nil
}
