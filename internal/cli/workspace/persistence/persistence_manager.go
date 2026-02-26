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

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/pkg/core/files"
)

// RelativeDir represents the relative directory type.
type RelativeDir uint8

const (
	// WorkDir is the current working directory.
	WorkDir RelativeDir = iota
	// WorkspaceDir is the workspace directory.
	WorkspaceDir RelativeDir = 1
	// PermguardDir is the permguard hiden directory.
	PermguardDir RelativeDir = 2
)

// Manager implements the internal manager for the persistence file.
type Manager struct {
	rootDir      string
	permguardDir string
	ctx          *common.CliCommandContext
}

// NewManager creates a new persistenceuration manager.
func NewManager(rootDir string, permguardDir string, ctx *common.CliCommandContext) (*Manager, error) {
	return &Manager{
		rootDir:      rootDir,
		permguardDir: permguardDir,
		ctx:          ctx,
	}, nil
}

// RelativeDir gets the relative directory.
func (p *Manager) RelativeDir(relative RelativeDir, name string) string {
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

// Context gets the context.
func (p *Manager) Context() map[string]string {
	absRootDir, _ := filepath.Abs(p.rootDir)
	absPermguardDir, _ := filepath.Abs(p.permguardDir)

	return map[string]string{
		"root path":               p.rootDir,
		"root absolute path":      absRootDir,
		"permguard path":          p.permguardDir,
		"permguard absolute path": absPermguardDir,
	}
}

// Path gets the path.
func (p *Manager) Path(relative RelativeDir, name string) string {
	name = p.RelativeDir(relative, name)
	return name
}

// CheckPathIfExists checks if a file exists.
func (p *Manager) CheckPathIfExists(relative RelativeDir, name string) (bool, error) {
	name = p.RelativeDir(relative, name)
	return files.CheckPathIfExists(name)
}

// DeletePath deletes a file or directory.
func (p *Manager) DeletePath(relative RelativeDir, name string) (bool, error) {
	name = p.RelativeDir(relative, name)
	return files.DeletePath(name)
}

// CreateDirIfNotExists creates a directory if it does not exist.
func (p *Manager) CreateDirIfNotExists(relative RelativeDir, name string) (bool, error) {
	name = p.RelativeDir(relative, name)
	return files.CreateDirIfNotExists(name)
}

// CreateFileIfNotExists creates a file if it does not exist.
func (p *Manager) CreateFileIfNotExists(relative RelativeDir, name string) (bool, error) {
	name = p.RelativeDir(relative, name)
	return files.CreateFileIfNotExists(name)
}

// WriteFileIfNotExists writes a file if it does not exist.
func (p *Manager) WriteFileIfNotExists(relative RelativeDir, name string, data []byte, perm os.FileMode, compressed bool) (bool, error) {
	name = p.RelativeDir(relative, name)
	return files.WriteFileIfNotExists(name, data, perm, compressed)
}

// WriteFile writes a file.
func (p *Manager) WriteFile(relative RelativeDir, name string, data []byte, perm os.FileMode, compressed bool) (bool, error) {
	name = p.RelativeDir(relative, name)
	return files.WriteFile(name, data, perm, compressed)
}

// AppendToFile appends to a file.
func (p *Manager) AppendToFile(relative RelativeDir, name string, data []byte, compressed bool) (bool, error) {
	name = p.RelativeDir(relative, name)
	return files.AppendToFile(name, data, compressed)
}

// ReadFile reads a file.
func (p *Manager) ReadFile(relative RelativeDir, name string, compressed bool) ([]byte, uint32, error) {
	name = p.RelativeDir(relative, name)
	return files.ReadFile(name, compressed)
}

// ListDirectories lists directories.
func (p *Manager) ListDirectories(relative RelativeDir, name string) ([]string, error) {
	name = p.RelativeDir(relative, name)
	return files.ListDirectories(name)
}

// ListFiles lists files.
func (p *Manager) ListFiles(relative RelativeDir, name string) ([]string, error) {
	name = p.RelativeDir(relative, name)
	return files.ListFiles(name)
}

// ScanAndFilterFiles scans and filters files.
func (p *Manager) ScanAndFilterFiles(relative RelativeDir, name string, exts []string, ignorePatterns []string, ignoreFile string) ([]string, []string, error) {
	name = p.RelativeDir(relative, name)
	ignoreFile = p.RelativeDir(relative, ignoreFile)
	ignoreFilePatterns, err := files.ReadIgnoreFile(ignoreFile)
	if err == nil {
		ignorePatterns = append(ignorePatterns, ignoreFilePatterns...)
	}
	return files.ScanAndFilterFiles(name, exts, ignorePatterns)
}

// WriteCSVStream writes a CSV stream.
func (p *Manager) WriteCSVStream(relative RelativeDir, name string, header []string, records any, rowFunc func(any) []string, compressed bool) error {
	name = p.RelativeDir(relative, name)
	return files.WriteCSVStream(name, header, records, rowFunc, compressed)
}

// ReadCSVStream reads from a CSV stream.
func (p *Manager) ReadCSVStream(relative RelativeDir, name string, header []string, recordFunc func([]string) error, compressed bool) error {
	name = p.RelativeDir(relative, name)
	return files.ReadCSVStream(name, header, recordFunc, compressed)
}

// ReadTOMLFile reads a TOML file.
func (p *Manager) ReadTOMLFile(relative RelativeDir, name string, v any) error {
	name = p.RelativeDir(relative, name)
	return files.ReadTOMLFile(name, v)
}
