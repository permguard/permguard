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

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azfiles "github.com/permguard/permguard/pkg/core/files"
)

type RelativeDir uint8

const (
	// WorkDir is the current working directory.
	WorkDir RelativeDir = iota
	// WorkspaceDir is the workspace directory.
	WorkspaceDir RelativeDir = 1
	// PermguardDir is the permguard hiden directory.
	PermguardDir RelativeDir = 2
)

// PersistenceManager implements the internal manager for the persistence file.
type PersistenceManager struct {
	rootDir      string
	permguardDir string
	ctx          *aziclicommon.CliCommandContext
}

// NewPersistenceManager creates a new persistenceuration manager.
func NewPersistenceManager(rootDir string, permguardDir string, ctx *aziclicommon.CliCommandContext) (*PersistenceManager, error) {
	return &PersistenceManager{
		rootDir:      rootDir,
		permguardDir: permguardDir,
		ctx:          ctx,
	}, nil
}

// GetRelativeDir gets the relative directory.
func (p *PersistenceManager) GetRelativeDir(relative RelativeDir, name string) string {
	switch relative {
	case WorkDir:
		return name
	case WorkspaceDir:
		return filepath.Join(p.rootDir, name)
	case PermguardDir:
		return filepath.Join(p.rootDir, p.permguardDir, name)
	}
	return p.rootDir
}

// GetContext gets the context.
func (p *PersistenceManager) GetContext() map[string]string {
	absRootDir, _ := filepath.Abs(p.rootDir)
	absPermguardDir, _ := filepath.Abs(p.permguardDir)

	return map[string]string{
		"root path":               p.rootDir,
		"root absolute path":      absRootDir,
		"permguard path":          p.permguardDir,
		"permguard absolute path": absPermguardDir,
	}
}

// GetPath gets the path.
func (p *PersistenceManager) GetPath(relative RelativeDir, name string) string {
	name = p.GetRelativeDir(relative, name)
	return name
}

// CheckPathIfExists checks if a file exists.
func (p *PersistenceManager) CheckPathIfExists(relative RelativeDir, name string) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.CheckPathIfExists(name)
}

// DeleteFile deletes a file.
func (p *PersistenceManager) DeletePath(relative RelativeDir, name string) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.DeletePath(name)
}

// CreateDirIfNotExists creates a directory if it does not exist.
func (p *PersistenceManager) CreateDirIfNotExists(relative RelativeDir, name string) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.CreateDirIfNotExists(name)
}

// CreateFileIfNotExists creates a file if it does not exist.
func (p *PersistenceManager) CreateFileIfNotExists(relative RelativeDir, name string) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.CreateFileIfNotExists(name)
}

// WriteFileIfNotExists writes a file if it does not exist.
func (p *PersistenceManager) WriteFileIfNotExists(relative RelativeDir, name string, data []byte, perm os.FileMode, compressed bool) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.WriteFileIfNotExists(name, data, perm, compressed)
}

// WriteFile writes a file.
func (p *PersistenceManager) WriteFile(relative RelativeDir, name string, data []byte, perm os.FileMode, compressed bool) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.WriteFile(name, data, perm, compressed)
}

// AppendToFile appends to a file.
func (p *PersistenceManager) AppendToFile(relative RelativeDir, name string, data []byte, compressed bool) (bool, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.AppendToFile(name, data, compressed)
}

// ReadFile reads a file.
func (p *PersistenceManager) ReadFile(relative RelativeDir, name string, compressed bool) ([]byte, uint32, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.ReadFile(name, compressed)
}

// ListDirectories lists directories.
func (p *PersistenceManager) ListDirectories(relative RelativeDir, name string) ([]string, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.ListDirectories(name)
}

// ListFiles lists files.
func (p *PersistenceManager) ListFiles(relative RelativeDir, name string) ([]string, error) {
	name = p.GetRelativeDir(relative, name)
	return azfiles.ListFiles(name)
}

// ScanAndFilterFiles scans and filters files.
func (p *PersistenceManager) ScanAndFilterFiles(relative RelativeDir, name string, exts []string, ignorePatterns []string, ignoreFile string) ([]string, []string, error) {
	name = p.GetRelativeDir(relative, name)
	ignoreFile = p.GetRelativeDir(relative, ignoreFile)
	ignoreFilePatterns, err := azfiles.ReadIgnoreFile(ignoreFile)
	if err == nil {
		ignorePatterns = append(ignorePatterns, ignoreFilePatterns...)
	}
	return azfiles.ScanAndFilterFiles(name, exts, ignorePatterns)
}

// WriteCSVStream writes a CSV stream.
func (p *PersistenceManager) WriteCSVStream(relative RelativeDir, name string, header []string, records any, rowFunc func(any) []string, compressed bool) error {
	name = p.GetRelativeDir(relative, name)
	return azfiles.WriteCSVStream(name, header, records, rowFunc, compressed)
}

// ReadCSVStream reads from a CSV stream.
func (p *PersistenceManager) ReadCSVStream(relative RelativeDir, name string, header []string, recordFunc func([]string) error, compressed bool) error {
	name = p.GetRelativeDir(relative, name)
	return azfiles.ReadCSVStream(name, header, recordFunc, compressed)
}

// ReadTOMLFile reads a TOML file.
func (p *PersistenceManager) ReadTOMLFile(relative RelativeDir, name string, v any) error {
	name = p.GetRelativeDir(relative, name)
	return azfiles.ReadTOMLFile(name, v)
}
