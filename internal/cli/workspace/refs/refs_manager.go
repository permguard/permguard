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
	azcrypto "github.com/permguard/permguard/pkg/extensions/crypto"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

const (
	// hiddenRefsDir represents the hidden refs directory.
	hiddenRefsDir = "refs"
	// hiddenHeadFile represents the hidden head file.
	hiddenHeadFile = "HEAD"
)

// RefsManager implements the internal manager for the refs file.
type RefsManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
}

// NewRefsManager creates a new refsuration manager.
func NewRefsManager(ctx *aziclicommon.CliCommandContext, persMgr *azicliwkspers.PersistenceManager) *RefsManager {
	return &RefsManager{
		ctx:     ctx,
		persMgr: persMgr,
	}
}

// getRefsDir returns the refs directory.
func (m *RefsManager) getRefsDir() string {
	return hiddenRefsDir
}

// getHeadFile returns the head file.
func (m *RefsManager) getHeadFile() string {
	return hiddenHeadFile
}

// saveConfig saves the configuration file.
func (m *RefsManager) saveConfig(fileName string, override bool, cfg interface{}) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to marshal config")
	}
	if override {
		_, err = m.persMgr.WriteFile(true, fileName, data, 0644)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(true, fileName, data, 0644)
	}
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: failed to write config file %s", fileName))
	}
	return nil
}

// Initalize the refs resources.
func (m *RefsManager) Initalize() error {
	_, err := m.persMgr.CreateDirIfNotExists(true, m.getRefsDir())
	if err != nil {
		return err
	}
	headFile := m.getHeadFile()
	_, err = m.persMgr.CreateFileIfNotExists(true, headFile)
	if err != nil {
		return err
	}
	return nil
}

// readConfig reads the configuration file.
func (m *RefsManager) readHeadConfig() (*HeadConfig, error) {
	var config HeadConfig
	err := m.persMgr.ReadTOMLFile(true, m.getHeadFile(), &config)
	return &config, err
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
	refID := azcrypto.ComputeStringSHA1(ref)
	return refID, nil
}

// CalculateRefID calculate the ref ID
func (m *RefsManager) CalculateRefID(remote string, accountID int64, repo string) (string, error) {
	return m.CalculateRefIDWithBase("", remote, accountID, repo)
}

// GetCurrentHead gets the current head.
func (m *RefsManager) GetCurrentHead() (string, int64, string, string, error) {
	cfgHead, err := m.readHeadConfig()
	if err != nil {
		return "", 0, "", "", err
	}
	return cfgHead.Head.Remote, cfgHead.Head.AccountID, cfgHead.Head.Repo, cfgHead.Head.RefID, nil
}

// GetCurrentHeadRef gets the current head ref.
func (m *RefsManager) GetCurrentHeadRef() (string, error) {
	remote, accountID, repo, _, err := m.GetCurrentHead()
	if err != nil {
		return "", err
	}
	return m.GetRef(remote, accountID, repo)
}

// CalculateCurrentHeadRefID gets the current head ref ID.
func (m *RefsManager) CalculateCurrentHeadRefID() (string, error) {
	remote, accountID, repo, _, err := m.GetCurrentHead()
	if err != nil {
		return "", err
	}
	return m.CalculateRefID(remote, accountID, repo)
}

// createAndGetHeadRefFile creates and gets the head ref file.
func (m *RefsManager) createAndGetHeadRefFile(remote string, refID string) (string, error) {
	refDir := filepath.Join(hiddenRefsDir, remote)
	_, err := m.persMgr.CreateDirIfNotExists(true, refDir)
	if err != nil {
		return "", err
	}
	refPath := filepath.Join(refDir, refID)
	return refPath, err
}

// CheckoutHead checks out the head.
func (m *RefsManager) CheckoutHead(remote string, accountID int64, repo string, commit string, output map[string]any, out func(map[string]any, string, any, error) map[string]any) (string, string, map[string]any, error) {
	refID, err := m.CalculateRefID(remote, accountID, repo)
	if err != nil {
		return "", "", nil, err
	}
	refPath, err := m.createAndGetHeadRefFile(remote, refID)
	if err != nil {
		return "", "", nil, err
	}
	refCfg := RefsConfig{
		Objects: RefsObjectsConfig{
			Commit: commit,
		},
	}
	err = m.saveConfig(refPath, true, &refCfg)
	if err != nil {
		return "", "", nil, err
	}
	headCfg := HeadConfig{
		Head: HeadRefsConfig{
			Remote:    remote,
			AccountID: accountID,
			Repo:      repo,
			RefID:     refID,
		},
	}
	headFile := m.getHeadFile()
	err = m.saveConfig(headFile, true, &headCfg)
	if err != nil {
		return "", "", nil, err
	}
	if m.ctx.IsTerminalOutput() {
		output = out(nil, "head", refPath, nil)
	} else {
		remotes := []interface{}{}
		remoteObj := map[string]any{
			"remote":    headCfg.Head.Remote,
			"accountid": headCfg.Head.AccountID,
			"repo":      headCfg.Head.Repo,
			"refs":      headCfg.Head.RefID,
		}
		remotes = append(remotes, remoteObj)
		output = out(output, "head", remotes, nil)
	}
	ref, err := m.GetCurrentHeadRef()
	if err != nil {
		return "", "", nil, err
	}
	refID, err = m.CalculateCurrentHeadRefID()
	if err != nil {
		return "", "", nil, err
	}
	return ref, refID, output, nil
}
