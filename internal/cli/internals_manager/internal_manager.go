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
)

const (
	hiddenDir = ".permguard"
	hiddenLogsDir = "logs"
	hiddenObjectsDir = "objects"
	hiddenPlansDir = "plans"
	hiddenRefsDir = "refs"
)

// InternalManager implements the internal manager to manage the .permguard directory.
type InternalManager struct {
	workDirectory string
}

// NewInternalManager creates a new internal manager.
func NewInternalManager(workDirectory string) *InternalManager {
	return &InternalManager{
		workDirectory: workDirectory,
	}
}

// createDir creates a directory.
func (*InternalManager) createDir(dir string) (error) {
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

// Initialize initializes the internal manager.
func (m *InternalManager) Initialize() error {
	hiddenDir := filepath.Join(m.workDirectory, hiddenDir)
	dirs := []string{
		hiddenDir,
		filepath.Join(hiddenDir, hiddenLogsDir),
		filepath.Join(hiddenDir, hiddenObjectsDir),
		filepath.Join(hiddenDir, hiddenPlansDir),
		filepath.Join(hiddenDir, hiddenRefsDir),
	}
	for _, dir := range dirs {
		err := m.createDir(dir)
		if err != nil {
			return err
		}
	}
	return nil
}
