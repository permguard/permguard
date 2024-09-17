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

package refs

import (
	"fmt"
	"path/filepath"

	"github.com/pelletier/go-toml"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// hiddenRefsDir represents the hidden refs directory.
	hiddenRefsDir = "refs"
	// hiddenHeadFile represents the hidden head file.
	hiddenHeadFile = "HEAD"
	// ZeroOID  represents the zero oid
	ZeroOID = "0000000000000000000000000000000000000000000000000000000000000000"
)

// RefsManager implements the internal manager for the refs files.
type RefsManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
}

// NewRefsManager creates a new refsuration manager.
func NewRefsManager(ctx *aziclicommon.CliCommandContext, persMgr *azicliwkspers.PersistenceManager) (*RefsManager, error) {
	return &RefsManager{
		ctx:     ctx,
		persMgr: persMgr,
	}, nil
}

// getRefsDir returns the refs directory.
func (m *RefsManager) getRefsDir() string {
	return hiddenRefsDir
}

// getHeadFile returns the head file.
func (m *RefsManager) getHeadFile() string {
	return hiddenHeadFile
}

// getRefsFile returns the refs file.
func (m *RefsManager) getRefsFile(refs string) (string, error) {
	refsInfo, err := convertStringToRefsInfo(refs)
	if err != nil {
		return "", err
	}
	return filepath.Join(hiddenRefsDir, refsInfo.remote, refsInfo.refID), nil
}

// ensureRefsFileExists ensures the refs file exists.
func (m *RefsManager) ensureRefsFileExists(refs string) error {
	refsFile, err := m.getRefsFile(refs)
	if err != nil {
		return err
	}
	_, err = m.persMgr.CreateFileIfNotExists(azicliwkspers.PermGuardDir, refsFile)
	if err != nil {
		return err
	}
	return err
}

// GenerateRefs generates the refs.
func (m *RefsManager) GenerateRefs(remote string, accountID int64, repo string, refID string) string {
	refsInfo := &RefsInfo{
		remote:    remote,
		accountID: accountID,
		repo:      repo,
	}
	refs := convertRefsInfoToString(refsInfo)
	return refs
}

// saveConfig saves the config file.
func (m *RefsManager) saveConfig(name string, override bool, cfg any) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to marshal config")
	}
	if override {
		_, err = m.persMgr.WriteFile(azicliwkspers.PermGuardDir, name, data, 0644, false)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(azicliwkspers.PermGuardDir, name, data, 0644, false)
	}
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: failed to write config file %s", name))
	}
	return nil
}

// SaveHeadConfig saves the head config file.
func (m *RefsManager) SaveHeadConfig(refs string) error {
	headFile := m.getHeadFile()
	headCfg := headConfig{
		Reference: headReferenceConfig{
			Refs: refs,
		},
	}
	err := m.saveConfig(headFile, true, &headCfg)
	if err != nil {
		return err
	}
	return nil
}

// readHeadConfig reads the config file.
func (m *RefsManager) readHeadConfig() (*headConfig, error) {
	var config headConfig
	err := m.persMgr.ReadTOMLFile(azicliwkspers.PermGuardDir, m.getHeadFile(), &config)
	return &config, err
}

// SaveRefsConfig saves the refs configuration.
func (m *RefsManager) SaveRefsConfig(refs string, commit string) error {
	err := m.ensureRefsFileExists(refs)
	if err != nil {
		return err
	}
	refsPath, err := m.getRefsFile(refs)
	if err != nil {
		return err
	}
	refCfg := refsConfig{
		Objects: refsObjectsConfig{
			Commit: commit,
		},
	}
	err = m.saveConfig(refsPath, true, &refCfg)
	if err != nil {
		return err
	}
	return nil
}

// readRefsConfig reads the refs configuration.
func (m *RefsManager) readRefsConfig(refs string) (*refsConfig, error) {
	refsPath, err := m.getRefsFile(refs)
	if err != nil {
		return nil, err
	}
	var config refsConfig
	err = m.persMgr.ReadTOMLFile(azicliwkspers.PermGuardDir, refsPath, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// GetRefsCommit reads the refs commit.
func (m *RefsManager) GetRefsCommit(refs string) (string, error) {
	refsCfg, err := m.readRefsConfig(refs)
	if err != nil {
		return "", err
	}
	if refsCfg == nil {
		return "", azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: invalid refs config file")

	}
	return refsCfg.Objects.Commit, nil
}

// GetCurrentHead gets the current head.
func (m *RefsManager) GetCurrentHead() (*HeadInfo, error) {
	cfgHead, err := m.readHeadConfig()
	if err != nil {
		return nil, err
	}
	return &HeadInfo{
		refs: cfgHead.Reference.Refs,
	}, nil
}

// GetCurrentHeadRefs gets the current head ref.
func (m *RefsManager) GetCurrentHeadRefs() (string, error) {
	headInfo, err := m.GetCurrentHead()
	if err != nil {
		return "", err
	}
	return headInfo.refs, nil
}

// GetCurrentHeadCommit gets the current head commit.
func (m *RefsManager) GetCurrentHeadCommit() (string, error) {
	headInfo, err := m.GetCurrentHead()
	if err != nil {
		return "", err
	}
	return m.GetRefsCommit(headInfo.refs)
}

// GetCurrentHeadRefsInfo gets the current head refs information.
func (m *RefsManager) GetCurrentHeadRefsInfo() (*RefsInfo, error) {
	headInfo, err := m.GetCurrentHead()
	if err != nil {
		return nil, err
	}
	return convertStringToRefsInfo(headInfo.refs)
}
