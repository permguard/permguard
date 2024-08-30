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

package internalmanager

import (
	"fmt"
	"os"
	"path/filepath"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
)

const (
	hiddenDir        	= ".permguard"
	hiddenLogsDir    	= "logs"
	hiddenObjectsDir 	= "objects"
	hiddenPlansDir   	= "plans"
	hiddenRefsDir    	= "refs"
	hiddenConfigFile 	= "config"
	hiddenHeadFile		= "HEAD"
)

// InternalManager implements the internal manager to manage the .permguard directory.
type InternalManager struct {
	ctx     *aziclicommon.CliCommandContext
}

// NewInternalManager creates a new internal manager.
func NewInternalManager(ctx *aziclicommon.CliCommandContext) *InternalManager {
	return &InternalManager{
		ctx:     ctx,
	}
}

// createFileIfNotExists creates a file if it does not exist.
func (*InternalManager) createFileIfNotExists(filePath string) error {
    if _, err := os.Stat(filePath); err == nil {
        return fmt.Errorf("file %s already exists", filePath)
    } else if os.IsNotExist(err) {
        dir := filepath.Dir(filePath)
        err := os.MkdirAll(dir, 0755)
        if err != nil {
            return fmt.Errorf("failed to create directory %s: %v", dir, err)
        }
        file, err := os.Create(filePath)
        if err != nil {
            return fmt.Errorf("failed to create file %s: %v", filePath, err)
        }
        defer file.Close()
    } else {
        return fmt.Errorf("failed to stat file %s: %v", filePath, err)
    }
    return nil
}

// createDir creates a directory.
func (*InternalManager) createDir(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return fmt.Errorf("directory %s already exists", dir)
	} else if os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	} else {
		return fmt.Errorf("failed to stat directory %s: %v", dir, err)
	}
	return nil
}

// InitWorkspace the workspace.
func (m *InternalManager) InitWorkspace() (string, error) {
	hdnDir := filepath.Join(m.ctx.GetWorkDir(), hiddenDir)
	hdnLogsDir := filepath.Join(hdnDir, hiddenLogsDir)
	hdnObjectsDir := filepath.Join(hdnDir, hiddenObjectsDir)
	hdnPlansDir:= filepath.Join(hdnDir, hiddenPlansDir)
	hdnRefsDir:= filepath.Join(hdnDir, hiddenRefsDir)

	firstInit := true
	err := m.createDir(hdnDir)
	if err != nil {
		firstInit = false
	}
	dirs := []string{
		hdnLogsDir,
		hdnObjectsDir,
		hdnPlansDir,
		hdnRefsDir,
	}
	for _, dir := range dirs {
		err := m.createDir(dir)
		if err != nil {
			return "", err
		}
	}
	hdConfigFile := filepath.Join(hdnDir, hiddenConfigFile)
	hdHeadFile := filepath.Join(hdnDir, hiddenHeadFile)
	files := []string{
		hdConfigFile,
		hdHeadFile,
	}
	for _, file := range files {
		err := m.createFileIfNotExists(file)
		if err != nil {
			return "", err
		}
	}
	var output string
	if firstInit {
		output = fmt.Sprintf("Initialized empty panicermGuard repository in %s", hdnDir)
	} else {
		output = fmt.Sprintf("Reinitialized existing permGuard repository in %s", hdnDir)
	}
	return output, nil
}
