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
	"os"
	"path/filepath"

	azfiles "github.com/permguard/permguard-core/pkg/extensions/files"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
)

// PersistenceManager implements the internal manager for the persistence file.
type PersistenceManager struct {
	rootDir string
	ctx     *aziclicommon.CliCommandContext
}

// NewPersistenceManager creates a new persistenceuration manager.
func NewPersistenceManager(rootDir string, ctx *aziclicommon.CliCommandContext) *PersistenceManager {
	return &PersistenceManager{
		rootDir: rootDir,
		ctx:     ctx,
	}
}

// CheckFileIfExists checks if a file exists.
func (p *PersistenceManager) CheckFileIfExists(relative bool, name string) (bool, error) {
	if relative {
		name = filepath.Join(p.rootDir, name)
	}
	return azfiles.CheckFileIfExists(name)
}

// CreateFileIfNotExists creates a file if it does not exist.
func (p *PersistenceManager) CreateFileIfNotExists(relative bool, name string) (bool, error) {
	if relative {
		name = filepath.Join(p.rootDir, name)
	}
	return azfiles.CreateFileIfNotExists(name)
}

// CreateDirIfNotExists creates a directory if it does not exist.
func (p *PersistenceManager) CreateDirIfNotExists(relative bool, name string) (bool, error) {
	if relative {
		name = filepath.Join(p.rootDir, name)
	}
	return azfiles.CreateDirIfNotExists(name)
}

// WriteFileIfNotExists writes a file if it does not exist.
func (p *PersistenceManager) WriteFileIfNotExists(relative bool, name string, data []byte, perm os.FileMode) (bool, error) {
	if relative {
		name = filepath.Join(p.rootDir, name)
	}
	return azfiles.WriteFileIfNotExists(name, data, perm)
}

// WriteFile writes a file.
func (p *PersistenceManager) WriteFile(relative bool, name string, data []byte, perm os.FileMode) (bool, error) {
	if relative {
		name = filepath.Join(p.rootDir, name)
	}
	return azfiles.WriteFile(name, data, perm)
}

// AppendToFile appends to a file.
func (p *PersistenceManager) AppendToFile(relative bool, name string, data []byte) (bool, error) {
	if relative {
		name = filepath.Join(p.rootDir, name)
	}
	return azfiles.AppendToFile(name, data)
}

// ReadTOMLFile reads a TOML file.
func (p *PersistenceManager) ReadTOMLFile(relative bool, name string, v any) error {
	if relative {
		name = filepath.Join(p.rootDir, name)
	}
	return azfiles.ReadTOMLFile(name, v)
}

// IsInsideDir checks if a directory is inside another directory.
func (p *PersistenceManager) IsInsideDir(name string) (bool, error) {
	return azfiles.IsInsideDir(name)
}
