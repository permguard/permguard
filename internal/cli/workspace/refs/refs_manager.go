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

	azcrypto "github.com/permguard/permguard-core/pkg/extensions/crypto"
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

// RefsManager implements the internal manager for the refs file.
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

// readHeadConfig reads the config file.
func (m *RefsManager) readHeadConfig() (*headConfig, error) {
	var config headConfig
	err := m.persMgr.ReadTOMLFile(azicliwkspers.PermGuardDir, m.getHeadFile(), &config)
	return &config, err
}

// ReadRefsCommit reads the refs commit.
func (m *RefsManager) ReadRefsCommit(remote string, refID string) (string, error) {
	_, refsCfg, err := m.readRefsConfig(remote, refID)
	if err != nil {
		return "", err
	}
	if refsCfg == nil {
		return "", azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: invalid refs config file")

	}
	return refsCfg.Objects.Commit, nil
}

// GetHeadRefsFile creates and gets the head ref file.
func (m *RefsManager) GetHeadRefsFile(remote string, refID string) (string, error) {
	refDir := filepath.Join(hiddenRefsDir, remote)
	_, err := m.persMgr.CreateDirIfNotExists(azicliwkspers.PermGuardDir, refDir)
	if err != nil {
		return "", err
	}
	refPath := filepath.Join(refDir, refID)
	return refPath, err
}

// readRefsConfig reads the refs configuration.
func (m *RefsManager) readRefsConfig(remote string, refID string) (string, *refsConfig, error) {
	refPath, err := m.GetHeadRefsFile(remote, refID)
	if err != nil {
		return refPath, nil, err
	}
	var config refsConfig
	err = m.persMgr.ReadTOMLFile(azicliwkspers.PermGuardDir, refPath, &config)
	if err != nil {
		return refPath, nil, err
	}
	return refPath, &config, nil
}

// SaveRefsConfig saves the refs configuration.
func (m *RefsManager) SaveRefsConfig(remote string, refID string, commit string) (error) {
	refPath, err := m.GetHeadRefsFile(remote, refID)
	if err != nil {
		return err
	}
	refCfg := refsConfig{
		Objects: refsObjectsConfig{
			Commit: commit,
		},
	}
	err = m.saveConfig(refPath, true, &refCfg)
	if err != nil {
		return err
	}
	return nil
}

// GetRefWithBase gets the ref with base.
func (m *RefsManager) GetRefWithBase(base string, remote string, accountID int64, repo string) (string, error) {
	var ref string
	if base != "" {
		ref = fmt.Sprintf("%s/%s/%d/%s", base, remote, accountID, repo)
	} else {
		ref = fmt.Sprintf("%s/%d/%s", remote, accountID, repo)
	}
	return ref, nil
}

// GetRef gets the ref.
func (m *RefsManager) GetRef(remote string, accountID int64, repo string) (string, error) {
	return m.GetRefWithBase("", remote, accountID, repo)
}

// CalculateRefIDWithBase calculate the ref ID with base
func (m *RefsManager) CalculateRefIDWithBase(base string, remote string, accountID int64, repo string) (string, error) {
	ref, err := m.GetRefWithBase(base, remote, accountID, repo)
	if err != nil {
		return "", err
	}
	refID := azcrypto.ComputeStringSHA256(ref)
	return refID, nil
}

// CalculateRefID calculate the ref ID
func (m *RefsManager) CalculateRefID(remote string, accountID int64, repo string) (string, error) {
	return m.CalculateRefIDWithBase("", remote, accountID, repo)
}

// GetCurrentHead gets the current head.
func (m *RefsManager) GetCurrentHead() (*HeadInfo, error) {
	cfgHead, err := m.readHeadConfig()
	if err != nil {
		return nil, err
	}
	return &HeadInfo{
		Remote:    cfgHead.Head.Remote,
		AccountID: cfgHead.Head.AccountID,
		Repo:      cfgHead.Head.Repo,
		RefID:     cfgHead.Head.RefID,
	}, nil
}

// GetCurrentHeadRef gets the current head ref.
func (m *RefsManager) GetCurrentHeadRef() (string, error) {
	headInfo, err := m.GetCurrentHead()
	if err != nil {
		return "", err
	}
	return m.GetRef(headInfo.Remote, headInfo.AccountID, headInfo.Repo)
}

// CalculateCurrentHeadRefID gets the current head ref ID.
func (m *RefsManager) CalculateCurrentHeadRefID() (string, error) {
	headInfo, err := m.GetCurrentHead()
	if err != nil {
		return "", err
	}
	return m.CalculateRefID(headInfo.Remote, headInfo.AccountID, headInfo.Repo)
}
