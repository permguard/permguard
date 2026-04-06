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
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml"

	"github.com/permguard/permguard/internal/cli/common"
	azwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
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

// Manager implements the internal manager for code, objs, states and plans.
type Manager struct {
	ctx     *common.CliCommandContext
	persMgr *persistence.Manager
	objMgr  *objects.ObjectManager
}

// NewPlansManager creates a new plansuration manager.
func NewPlansManager(ctx *common.CliCommandContext, persMgr *persistence.Manager) (*Manager, error) {
	objMgr, err := objects.NewObjectManager()
	if err != nil {
		return nil, err
	}
	return &Manager{
		ctx:     ctx,
		persMgr: persMgr,
		objMgr:  objMgr,
	}, nil
}

// codeDir returns the code directory.
func (m *Manager) codeDir() string {
	return hiddenCodeDir
}

// objectsDir returns the objs directory.
func (m *Manager) objectsDir() string {
	return hiddenObjectsDir
}

// codeSourceDir returns the code source directory.
func (m *Manager) codeSourceDir() string {
	return filepath.Join(m.codeDir(), hiddenSourceCodeDir)
}

// codeSourceObjectsDir returns the code source objs directory.
func (m *Manager) codeSourceObjectsDir() string {
	return filepath.Join(m.codeSourceDir(), m.objectsDir())
}

// codeSourceConfigFile returns the code source config file.
func (m *Manager) codeSourceConfigFile() string {
	return filepath.Join(m.codeSourceDir(), hiddenConfigFile)
}

// codeSourceObjectDir returns the code source object directory.
// It shards objects into subdirectories using the last two characters of the OID (CID format)
// to ensure even distribution (base32 suffix provides uniform hashing across 1024 buckets).
func (m *Manager) codeSourceObjectDir(oid string, basePath string) (string, string) {
	basePath = filepath.Join(basePath, m.objectsDir())
	folder := oid[len(oid)-2:]
	folder = filepath.Join(basePath, folder)
	name := oid[:len(oid)-2]
	return folder, name
}

// CleanCodeSource cleans the code source area.
// Post-condition: after a successful call, the code source directory does not exist.
func (m *Manager) CleanCodeSource() (bool, error) {
	cleaned, err := m.persMgr.DeletePath(persistence.PermguardDir, m.codeSourceDir())
	if err != nil {
		return false, errors.Join(errors.New("cli: failed to clean code source area"), err)
	}
	return cleaned, nil
}

// IsCodeSourceClean checks if the code source area is empty or does not exist.
func (m *Manager) IsCodeSourceClean() (bool, error) {
	exists, err := m.persMgr.CheckPathIfExists(persistence.PermguardDir, m.codeSourceDir())
	if err != nil {
		return false, err
	}
	return !exists, nil
}

// SaveCodeSourceObject saves the object in the code source.
func (m *Manager) SaveCodeSourceObject(oid string, content []byte) (bool, error) {
	folder, name := m.codeSourceObjectDir(oid, m.codeSourceDir())
	path := filepath.Join(folder, name)
	_, err := m.persMgr.CreateDirIfNotExists(persistence.PermguardDir, folder)
	if err != nil {
		return false, errors.Join(fmt.Errorf("cli: failed to save object %s", oid), err)
	}
	return m.persMgr.WriteFile(persistence.PermguardDir, path, content, 0o644, true)
}

// ReadCodeSourceObject reads the object from the code source and verifies OID integrity.
func (m *Manager) ReadCodeSourceObject(oid string) (*objects.Object, error) {
	folder, name := m.codeSourceObjectDir(oid, m.codeSourceDir())
	path := filepath.Join(folder, name)
	data, _, err := m.persMgr.ReadFile(persistence.PermguardDir, path, true)
	if err != nil {
		return nil, err
	}
	if err := objects.VerifyOID(oid, data); err != nil {
		return nil, fmt.Errorf("cli: corrupted code source object %s: %w", oid, err)
	}
	return m.objMgr.DeserializeObjectFromBytes(data)
}

// saveConfig saves the config file.
func (m *Manager) saveConfig(name string, override bool, cfg any) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return errors.Join(errors.New("cli: failed to marshal config"), err)
	}
	if override {
		_, err = m.persMgr.WriteFile(persistence.PermguardDir, name, data, 0o644, false)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(persistence.PermguardDir, name, data, 0o644, false)
	}
	if err != nil {
		return fmt.Errorf("cli: failed to write config file %s", name)
	}
	return nil
}

// SaveCodeSourceConfig saves the code source config file.
func (m *Manager) SaveCodeSourceConfig(treeID string) error {
	config := &codeLocalConfig{
		CodeState: codeStateConfig{
			TreeID: treeID,
		},
	}
	file := m.codeSourceConfigFile()
	return m.saveConfig(file, true, config)
}

// SaveCodeSourceCodeMap saves the code map in the code source.
func (m *Manager) SaveCodeSourceCodeMap(codeFiles []CodeFile) error {
	_, err := m.persMgr.CreateDirIfNotExists(persistence.PermguardDir, m.codeSourceDir())
	if err != nil {
		return errors.Join(errors.New("cli: failed to create code plan"), err)
	}
	path := filepath.Join(m.codeSourceDir(), hiddenCodeMapFile)
	rowFunc := func(record any) []string {
		codeFile, ok := record.(CodeFile)
		if !ok {
			return nil
		}
		return []string{
			codeFile.Path,
			codeFile.OID,
			codeFile.OType,
			codeFile.OName,
			codeFile.CodeID,
			strconv.FormatUint(uint64(codeFile.CodeTypeID), 10),
			strconv.FormatUint(uint64(codeFile.LanguageID), 10),
			strconv.FormatUint(uint64(codeFile.LanguageVersionID), 10),
			strconv.FormatUint(uint64(codeFile.LanguageTypeID), 10),
			fmt.Sprintf("%d", codeFile.Mode),
			strconv.Itoa(codeFile.Section),
			strconv.FormatBool(codeFile.HasErrors),
			codeFile.Error,
		}
	}
	err = m.persMgr.WriteCSVStream(persistence.PermguardDir, path, nil, codeFiles, rowFunc, true)
	if err != nil {
		return errors.Join(errors.New("cli: failed to write code map"), err)
	}
	return nil
}

// ReadCodeSourceCodeMap reads the code map from the code source.
func (m *Manager) ReadCodeSourceCodeMap() ([]CodeFile, error) {
	path := filepath.Join(m.codeSourceDir(), hiddenCodeMapFile)
	var codeFiles []CodeFile
	recordFunc := func(record []string) error {
		if len(record) < 13 {
			return errors.New("invalid record format")
		}
		codeTypeID64, err := strconv.ParseUint(record[5], 10, 32)
		if err != nil {
			return err
		}
		languageID64, err := strconv.ParseUint(record[6], 10, 32)
		if err != nil {
			return err
		}
		langVersionID64, err := strconv.ParseUint(record[7], 10, 32)
		if err != nil {
			return err
		}
		langTypeID64, err := strconv.ParseUint(record[8], 10, 32)
		if err != nil {
			return err
		}
		mode64, err := strconv.ParseUint(record[9], 10, 32)
		if err != nil {
			return err
		}
		section, err := strconv.Atoi(record[10])
		if err != nil {
			return err
		}
		hasErrors, err := strconv.ParseBool(record[11])
		if err != nil {
			return err
		}
		codeFile := CodeFile{
			Path:              record[0],
			OID:               record[1],
			OType:             record[2],
			OName:             record[3],
			CodeID:            record[4],
			CodeTypeID:        uint32(codeTypeID64),
			LanguageID:        uint32(languageID64),
			LanguageVersionID: uint32(langVersionID64),
			LanguageTypeID:    uint32(langTypeID64),
			Mode:              uint32(mode64),
			Section:           section,
			HasErrors:         hasErrors,
			Error:             record[12],
		}
		codeFiles = append(codeFiles, codeFile)
		return nil
	}
	err := m.persMgr.ReadCSVStream(persistence.PermguardDir, path, nil, recordFunc, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []CodeFile{}, nil
		}
		return nil, errors.Join(errors.New("cli: failed to read code map"), err)
	}

	return codeFiles, nil
}

// SaveCodeSourceCodeState saves the code object state in the code source.
func (m *Manager) SaveCodeSourceCodeState(codeObjects []CodeObjectState) error {
	path := filepath.Join(m.codeSourceDir(), hiddenCodeStateFile)
	return m.saveCodeObjectStates(path, codeObjects)
}

// ReadCodeSourceCodeState reads the code object state from the code source.
func (m *Manager) ReadCodeSourceCodeState() ([]CodeObjectState, error) {
	path := filepath.Join(m.codeSourceDir(), hiddenCodeStateFile)
	return m.readCodeObjectStates(path)
}

// BuildCodeSourceCodeStateForTree builds the code object state for the input tree.
func (m *Manager) BuildCodeSourceCodeStateForTree(tree *objects.Tree) ([]CodeObjectState, error) {
	if tree == nil {
		return nil, errors.New("cli: tree is nil")
	}
	codeObjectStates := []CodeObjectState{}
	for _, entry := range tree.Entries() {
		codeObjState := CodeObjectState{
			CodeObject: CodeObject{
				Partition:         tree.Partition(),
				OName:             entry.OName(),
				OType:             entry.OType(),
				OID:               entry.OID(),
				DataType:          entry.DataType(),
				CodeID:            entry.MetadataString(objects.MetaKeyCodeID),
				CodeTypeID:        entry.MetadataUint32(objects.MetaKeyCodeTypeID),
				LanguageID:        entry.MetadataUint32(objects.MetaKeyLanguageID),
				LanguageTypeID:    entry.MetadataUint32(objects.MetaKeyLanguageTypeID),
				LanguageVersionID: entry.MetadataUint32(objects.MetaKeyLanguageVersionID),
			},
			State: "",
		}
		codeObjectStates = append(codeObjectStates, codeObjState)
	}
	return codeObjectStates, nil
}

// SaveRemoteCodePlan saves the code plan for the input remote.
func (m *Manager) SaveRemoteCodePlan(ref string, codeObjects []CodeObjectState) error {
	path := filepath.Join(m.codeDir(), strings.ToLower(ref))
	_, err := m.persMgr.CreateDirIfNotExists(persistence.PermguardDir, path)
	if err != nil {
		return errors.Join(errors.New("cli: failed to create code plan"), err)
	}
	path = filepath.Join(path, hiddenCodePlanFile)
	return m.saveCodeObjectStates(path, codeObjects)
}

// ReadRemoteCodePlan reads the code plan from the input remote.
func (m *Manager) ReadRemoteCodePlan(ref string) ([]CodeObjectState, error) {
	path := filepath.Join(m.codeDir(), strings.ToLower(ref), hiddenCodePlanFile)
	return m.readCodeObjectStates(path)
}

// CleanCode cleans the code.
func (m *Manager) CleanCode(ref string) (bool, error) {
	path := filepath.Join(m.codeDir(), strings.ToLower(ref))
	return m.persMgr.DeletePath(persistence.PermguardDir, path)
}

// convertCodeFileToCodeObjectState converts the code file to the code object.
func (m *Manager) convertCodeFileToCodeObjectState(codeFile CodeFile) (*CodeObjectState, error) {
	if codeFile.OName == "" {
		return nil, errors.New("cli: code file name is empty")
	}
	if codeFile.OID == "" {
		return nil, errors.New("cli: code file OID is empty")
	}
	if codeFile.CodeID == "" {
		return nil, errors.New("cli: code file CodeID is empty")
	}
	if codeFile.CodeTypeID == 0 {
		return nil, errors.New("cli: code file code type id is zero")
	}
	if codeFile.LanguageID == 0 {
		return nil, errors.New("cli: code file language id is zero")
	}
	if codeFile.LanguageTypeID == 0 {
		return nil, errors.New("cli: code file language type id is zero")
	}
	return &CodeObjectState{
		CodeObject: CodeObject{
			Partition:         codeFile.Partition,
			OName:             codeFile.OName,
			OType:             codeFile.OType,
			OID:               codeFile.OID,
			CodeID:            codeFile.CodeID,
			CodeTypeID:        codeFile.CodeTypeID,
			LanguageID:        codeFile.LanguageID,
			LanguageVersionID: codeFile.LanguageVersionID,
			LanguageTypeID:    codeFile.LanguageTypeID,
		},
	}, nil
}

// saveCodeObjectStates saves the code objs states.
func (m *Manager) saveCodeObjectStates(path string, codeObjects []CodeObjectState) error {
	rowFunc := func(record any) []string {
		codeObject, ok := record.(CodeObjectState)
		if !ok {
			return nil
		}
		return []string{
			codeObject.State,
			codeObject.Partition,
			codeObject.OName,
			codeObject.OType,
			codeObject.OID,
			codeObject.CodeID,
			strconv.FormatUint(uint64(codeObject.CodeTypeID), 10),
			strconv.FormatUint(uint64(codeObject.LanguageID), 10),
			strconv.FormatUint(uint64(codeObject.LanguageVersionID), 10),
			strconv.FormatUint(uint64(codeObject.LanguageTypeID), 10),
		}
	}
	err := m.persMgr.WriteCSVStream(persistence.PermguardDir, path, nil, codeObjects, rowFunc, true)
	if err != nil {
		return errors.Join(errors.New("cli: failed to write code object state"), err)
	}
	return nil
}

// readCodeObjectStates reads the code objs states.
func (m *Manager) readCodeObjectStates(path string) ([]CodeObjectState, error) {
	var codeObjects []CodeObjectState
	recordFunc := func(record []string) error {
		if len(record) < 2 {
			return errors.New("invalid record format")
		}
		codeTypeID64, _ := strconv.ParseUint(record[6], 10, 32)
		langID64, _ := strconv.ParseUint(record[7], 10, 32)
		langVersionID64, _ := strconv.ParseUint(record[8], 10, 32)
		langTypeID64, _ := strconv.ParseUint(record[9], 10, 32)
		codeObject := CodeObjectState{
			State: record[0],
			CodeObject: CodeObject{
				Partition:         record[1],
				OName:             record[2],
				OType:             record[3],
				OID:               record[4],
				CodeID:            record[5],
				CodeTypeID:        uint32(codeTypeID64),
				LanguageID:        uint32(langID64),
				LanguageVersionID: uint32(langVersionID64),
				LanguageTypeID:    uint32(langTypeID64),
			},
		}
		codeObjects = append(codeObjects, codeObject)
		return nil
	}
	err := m.persMgr.ReadCSVStream(persistence.PermguardDir, path, nil, recordFunc, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []CodeObjectState{}, nil
		}
		return nil, errors.Join(errors.New("cli: failed to read code state"), err)
	}
	return codeObjects, nil
}

// ConvertCodeFilesToCodeObjectStates converts code files to code objs.
func (m *Manager) ConvertCodeFilesToCodeObjectStates(codeFiles []CodeFile) ([]CodeObjectState, error) {
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
func (m *Manager) CalculateCodeObjectsState(currentObjs []CodeObjectState, remoteObjs []CodeObjectState) []CodeObjectState {
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
func (m *Manager) SaveObject(oid string, content []byte) (bool, error) {
	folder, name := m.codeSourceObjectDir(oid, "")
	path := filepath.Join(folder, name)
	_, err := m.persMgr.CreateDirIfNotExists(persistence.PermguardDir, folder)
	if err != nil {
		return false, errors.Join(fmt.Errorf("cli: failed to save object %s", oid), err)
	}
	return m.persMgr.WriteFile(persistence.PermguardDir, path, content, 0o644, true)
}

// ReadObject reads the object from the objs store and verifies OID integrity.
func (m *Manager) ReadObject(oid string) (*objects.Object, error) {
	folder, name := m.codeSourceObjectDir(oid, "")
	path := filepath.Join(folder, name)
	data, _, err := m.persMgr.ReadFile(persistence.PermguardDir, path, true)
	if err != nil {
		return nil, err
	}
	if err := objects.VerifyOID(oid, data); err != nil {
		return nil, fmt.Errorf("cli: corrupted object %s: %w", oid, err)
	}
	return m.objMgr.DeserializeObjectFromBytes(data)
}

// ObjectAbsolutePath returns the absolute filesystem path of the stored object for the given OID.
func (m *Manager) ObjectAbsolutePath(oid string) (string, error) {
	folder, name := m.codeSourceObjectDir(oid, m.codeSourceDir())
	relPath := filepath.Join(folder, name)
	abs, err := filepath.Abs(m.persMgr.Path(persistence.PermguardDir, relPath))
	if err != nil {
		return "", err
	}
	return abs, nil
}

// CollectGarbage removes orphaned objects from the object store that are not reachable from the given commit.
// It walks the commit → tree → blob graph and deletes any objects not in the reachable set.
func (m *Manager) CollectGarbage(commitID string) (int, error) {
	if commitID == "" || commitID == objects.ZeroOID {
		return 0, nil
	}
	reachable := map[string]bool{}
	visited := map[string]bool{}
	currentID := commitID
	for currentID != objects.ZeroOID {
		if visited[currentID] {
			return 0, fmt.Errorf("cli: cycle detected in commit chain at %s", currentID)
		}
		visited[currentID] = true
		obj, err := m.ReadObject(currentID)
		if err != nil {
			return 0, fmt.Errorf("cli: gc aborted, failed to read commit %s: %w", currentID, err)
		}
		if obj == nil {
			return 0, fmt.Errorf("cli: gc aborted, missing commit %s", currentID)
		}
		reachable[obj.OID()] = true
		objInfo, err := m.objMgr.ObjectInfo(obj)
		if err != nil {
			return 0, fmt.Errorf("cli: gc aborted, failed to get object info for %s: %w", currentID, err)
		}
		commit, ok := objInfo.Instance().(*objects.Commit)
		if !ok {
			return 0, fmt.Errorf("cli: gc aborted, oid %s is not a commit", currentID)
		}
		treeObj, err := m.ReadObject(commit.Tree().String())
		if err != nil {
			return 0, fmt.Errorf("cli: gc aborted, failed to read tree %s: %w", commit.Tree(), err)
		}
		if treeObj == nil {
			return 0, fmt.Errorf("cli: gc aborted, missing tree %s", commit.Tree())
		}
		reachable[treeObj.OID()] = true
		treeInfo, err := m.objMgr.ObjectInfo(treeObj)
		if err != nil {
			return 0, fmt.Errorf("cli: gc aborted, failed to get tree info for %s: %w", commit.Tree(), err)
		}
		tree, ok := treeInfo.Instance().(*objects.Tree)
		if !ok {
			return 0, fmt.Errorf("cli: gc aborted, oid %s is not a tree", commit.Tree())
		}
		for _, entry := range tree.Entries() {
			reachable[entry.OID()] = true
		}
		if !commit.Parent().Valid {
			break
		}
		currentID = commit.Parent().String
	}
	allObjs, err := m.objects(m.objectsDir(), true)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, obj := range allObjs {
		if !reachable[obj.OID()] {
			folder, name := m.codeSourceObjectDir(obj.OID(), "")
			path := filepath.Join(folder, name)
			if _, err := m.persMgr.DeletePath(persistence.PermguardDir, path); err == nil {
				removed++
			}
		}
	}
	return removed, nil
}

// GetObjects returns the objs.
func (m *Manager) objects(path string, isStore bool) ([]objects.Object, error) {
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
			oid := fmt.Sprintf("%s%s", file, dir)
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

// Objects returns the objs.
func (m *Manager) Objects(includeStorage, includeCode bool) ([]objects.Object, error) {
	objs := []objects.Object{}
	if includeCode {
		if ok, _ := m.persMgr.CheckPathIfExists(persistence.PermguardDir, m.codeSourceObjectsDir()); ok {
			codeObjs, err := m.objects(m.codeSourceObjectsDir(), false)
			if err != nil {
				return nil, err
			}
			objs = append(objs, codeObjs...)
		}
	}
	if includeStorage {
		if ok, _ := m.persMgr.CheckPathIfExists(persistence.PermguardDir, m.objectsDir()); ok {
			storageObjs, err := m.objects(m.objectsDir(), true)
			if err != nil {
				return nil, err
			}
			objs = append(objs, storageObjs...)
		}
	}
	return objs, nil
}

// Commit gets the commit.
func (m *Manager) Commit(commitID string) (*objects.Commit, error) {
	obj, err := m.ReadObject(commitID)
	if err != nil {
		return nil, err
	}
	objInfo, err := m.objMgr.ObjectInfo(obj)
	if err != nil {
		return nil, err
	}
	if objInfo.Type() != objects.ObjectTypeCommit {
		return nil, fmt.Errorf("cli: oid %s is not a valid commit", commitID)
	}
	commit, ok := objInfo.Instance().(*objects.Commit)
	if !ok {
		return nil, fmt.Errorf("cli: oid %s has unexpected object instance type", commitID)
	}
	return commit, nil
}

// History gets the commit history.
func (m *Manager) History(commitID string) ([]azwkscommon.CommitInfo, error) {
	var commits []azwkscommon.CommitInfo
	commit, err := m.Commit(commitID)
	if err != nil {
		return nil, err
	}
	visited := map[string]bool{}
	for commit != nil {
		if visited[commitID] {
			return nil, fmt.Errorf("cli: cycle detected in commit history at %s", commitID)
		}
		visited[commitID] = true
		commitInfo, err := azwkscommon.NewCommitInfo(commitID, commit)
		if err != nil {
			return nil, err
		}
		commits = append(commits, *commitInfo)
		if !commit.Parent().Valid {
			break
		}
		parentID := commit.Parent().String
		commit, err = m.Commit(parentID)
		if err != nil {
			return nil, err
		}
		commitID = parentID
	}
	return commits, nil
}
