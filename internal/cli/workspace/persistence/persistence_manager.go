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

package persistence

import (
	"fmt"
	"os"
	"path/filepath"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
)

// PersistenceManager implements the internal manager for the persistence file.
type PersistenceManager struct {
	rootDir string
	ctx	*aziclicommon.CliCommandContext
}

// NewPersistenceManager creates a new persistenceuration manager.
func NewPersistenceManager(rootDir string, ctx *aziclicommon.CliCommandContext) *PersistenceManager {
	return &PersistenceManager{
		rootDir: rootDir,
		ctx:     ctx,
	}
}

// CreateFileIfNotExists creates a file if it does not exist.
func (p *PersistenceManager) CreateFileIfNotExists(relative bool, name string) error {
	if relative {
		name = filepath.Join(p.rootDir, name)
	}
    if _, err := os.Stat(name); err == nil {
        return fmt.Errorf("file %s already exists", name)
    } else if os.IsNotExist(err) {
        dir := filepath.Dir(name)
        err := os.MkdirAll(dir, 0755)
        if err != nil {
            return fmt.Errorf("failed to create directory %s: %v", dir, err)
        }
        file, err := os.Create(name)
        if err != nil {
            return fmt.Errorf("failed to create file %s: %v", name, err)
        }
        defer file.Close()
    } else {
        return fmt.Errorf("failed to stat file %s: %v", name, err)
    }
    return nil
}

// CreateDir creates a directory.
func (p *PersistenceManager) CreateDir(relative bool, name string) error {
	if relative {
		name = filepath.Join(p.rootDir, name)
	}
	if _, err := os.Stat(name); err == nil {
		return fmt.Errorf("directory %s already exists", name)
	} else if os.IsNotExist(err) {
		err := os.MkdirAll(name, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory %s: %v", name, err)
		}
	} else {
		return fmt.Errorf("failed to stat directory %s: %v", name, err)
	}
	return nil
}

// WriteFile writes a file.
func (p *PersistenceManager) WriteFile(relative bool, name string, data []byte, perm os.FileMode) error {
	if relative {
		name = filepath.Join(p.rootDir, name)
	}
	return os.WriteFile(name, data, 0644)
}
