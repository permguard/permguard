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

type RelativeDir uint8

const (
	// WorkDir is the current working directory.
	WorkDir RelativeDir = iota
	// WorkspaceDir is the workspace directory.
	WorkspaceDir RelativeDir = 1
	// PermGuardDir is the permguard hiden directory.
	PermGuardDir RelativeDir = 2
)

// PersistenceManager implements the internal manager for the persistence file.
type PersistenceManager struct {
	rootDir			string
	permguardDir 	string
	ctx     		*aziclicommon.CliCommandContext
}

// NewPersistenceManager creates a new persistenceuration manager.
func NewPersistenceManager(rootDir string, permguardDir string, ctx *aziclicommon.CliCommandContext) *PersistenceManager {
	return &PersistenceManager{
		rootDir: 		rootDir,
		permguardDir: 	permguardDir,
		ctx:			ctx,
	}
}

// GetRelativeDir gets the relative directory.
func (p *PersistenceManager) GetRelativeDir(relative RelativeDir, name string) string {
	switch relative {
	case WorkDir:
		return name
	case WorkspaceDir:
		return filepath.Join(p.rootDir, name)
	case PermGuardDir:
		return filepath.Join(p.rootDir, p.permguardDir, name)
	}
	return p.rootDir
}

// CheckFileIfExists checks if a file exists.
func (p *PersistenceManager) CheckFileIfExists(relative RelativeDir, name string) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.CheckFileIfExists(name)
}

// CreateFileIfNotExists creates a file if it does not exist.
func (p *PersistenceManager) CreateFileIfNotExists(relative RelativeDir, name string) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.CreateFileIfNotExists(name)
}

// CreateDirIfNotExists creates a directory if it does not exist.
func (p *PersistenceManager) CreateDirIfNotExists(relative RelativeDir, name string) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.CreateDirIfNotExists(name)
}

// WriteFileIfNotExists writes a file if it does not exist.
func (p *PersistenceManager) WriteFileIfNotExists(relative RelativeDir, name string, data []byte, perm os.FileMode) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.WriteFileIfNotExists(name, data, perm)
}

// WriteFile writes a file.
func (p *PersistenceManager) WriteFile(relative RelativeDir, name string, data []byte, perm os.FileMode) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.WriteFile(name, data, perm)
}

// WriteBinaryFile writes a binary file.
func (p *PersistenceManager) WriteBinaryFile(relative RelativeDir, name string, data []byte, perm os.FileMode) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.WriteFile(name, data, perm)
}

// AppendToFile appends to a file.
func (p *PersistenceManager) AppendToFile(relative RelativeDir, name string, data []byte) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.AppendToFile(name, data)
}

// IsInsideDir checks if a directory is inside another directory.
func (p *PersistenceManager) IsInsideDir(relative RelativeDir, name string) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.IsInsideDir(name)
}

// ScanAndFilterFiles scans and filters files.
func (p *PersistenceManager) ScanAndFilterFiles(relative RelativeDir, exts []string, ignorePatterns []string, ignoreFile string) ([]string, []string, error) {
	name := p.GetRelativeDir(relative, "")
	ignoreFile = p.GetRelativeDir(relative, ignoreFile)
	ignoreFilePatterns, err :=  azfiles.ReadIgnoreFile(ignoreFile)
	ignorePatterns = append(ignorePatterns, ignoreFilePatterns...)
	if err != nil {
		return nil, nil, err
	}
	return azfiles.ScanAndFilterFiles(name, exts, ignorePatterns)
}

// ReadTOMLFile reads a TOML file.
func (p *PersistenceManager) ReadTOMLFile(relative RelativeDir, name string, v any) error {
	name = p.GetRelativeDir(relative, name)
	return azfiles.ReadTOMLFile(name, v)
}
