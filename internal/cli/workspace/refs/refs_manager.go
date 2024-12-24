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

package ref

import (
	"fmt"
	"path/filepath"

	"github.com/pelletier/go-toml"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// hiddenRefsDir represents the hidden refs directory.
	hiddenRefsDir = "refs"
	// hiddenHeadFile represents the hidden head file.
	hiddenHeadFile = "HEAD"
)

// RefManager implements the internal manager for the ref files.
type RefManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
}

// NewRefManager creates a new refuration manager.
func NewRefManager(ctx *aziclicommon.CliCommandContext, persMgr *azicliwkspers.PersistenceManager) (*RefManager, error) {
	return &RefManager{
		ctx:     ctx,
		persMgr: persMgr,
	}, nil
}

// getRefsDir returns the refs directory.
func (m *RefManager) getRefsDir() string {
	return hiddenRefsDir
}

// getHeadFile returns the head file.
func (m *RefManager) getHeadFile() string {
	return hiddenHeadFile
}

// getRefFile returns the ref file.
func (m *RefManager) getRefFile(ref string) (string, error) {
	refInfo, err := azicliwkscommon.ConvertStringWithRepoIDToRefInfo(ref)
	if err != nil {
		return "", err
	}
	return filepath.Join(hiddenRefsDir, refInfo.GetSourceType(), refInfo.GetRemote(), fmt.Sprintf("%d", refInfo.GetApplicationID()), refInfo.GetRepoID()), nil
}

// ensureRefFileExists ensures the ref file exists.
func (m *RefManager) ensureRefFileExists(ref string) error {
	refFile, err := m.getRefFile(ref)
	if err != nil {
		return err
	}
	_, err = m.persMgr.CreateFileIfNotExists(azicliwkspers.PermguardDir, refFile)
	if err != nil {
		return err
	}
	return err
}

// GenerateRef generates the ref.
func (m *RefManager) GenerateRef(remote string, applicationID int64, repoID string) string {
	refInfo, _ := azicliwkscommon.NewRefInfoFromRepoName(remote, applicationID, repoID)
	ref := azicliwkscommon.ConvertRefInfoToString(refInfo)
	return ref
}

// saveConfig saves the config file.
func (m *RefManager) saveConfig(name string, override bool, cfg any) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to marshal config")
	}
	if override {
		_, err = m.persMgr.WriteFile(azicliwkspers.PermguardDir, name, data, 0644, false)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(azicliwkspers.PermguardDir, name, data, 0644, false)
	}
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: failed to write config file %s", name))
	}
	return nil
}

// SaveHeadConfig saves the head config file.
func (m *RefManager) SaveHeadConfig(ref string) error {
	headFile := m.getHeadFile()
	headCfg := headConfig{
		Reference: headReferenceConfig{
			Ref: ref,
		},
	}
	err := m.saveConfig(headFile, true, &headCfg)
	if err != nil {
		return err
	}
	return nil
}

// readHeadConfig reads the config file.
func (m *RefManager) readHeadConfig() (*headConfig, error) {
	var config headConfig
	err := m.persMgr.ReadTOMLFile(azicliwkspers.PermguardDir, m.getHeadFile(), &config)
	return &config, err
}

// SaveRefConfig saves the ref configuration.
func (m *RefManager) SaveRefConfig(repoID string, ref string, commit string) error {
	return m.SaveRefWithRemoteConfig(repoID, ref, "", commit)
}

// SaveRefWithRemoteConfig saves the ref with remote configuration.
func (m *RefManager) SaveRefWithRemoteConfig(repoID string, ref, upstreamRef string, commit string) error {
	err := m.ensureRefFileExists(ref)
	if err != nil {
		return err
	}
	refPath, err := m.getRefFile(ref)
	if err != nil {
		return err
	}
	refCfg := refConfig{
		Objects: refObjectsConfig{
			UpstreamRef: upstreamRef,
			RepoID:      repoID,
			Commit:      commit,
		},
	}
	err = m.saveConfig(refPath, true, &refCfg)
	if err != nil {
		return err
	}
	return nil
}

// readRefConfig reads the ref configuration.
func (m *RefManager) readRefConfig(ref string) (*refConfig, error) {
	refPath, err := m.getRefFile(ref)
	if err != nil {
		return nil, err
	}
	var config refConfig
	err = m.persMgr.ReadTOMLFile(azicliwkspers.PermguardDir, refPath, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// GetRefUpstreamRef reads the ref upstream ref.
func (m *RefManager) GetRefUpstreamRef(ref string) (string, error) {
	refCfg, err := m.readRefConfig(ref)
	if err != nil {
		return "", err
	}
	if refCfg == nil {
		return "", azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: invalid ref config file")

	}
	return refCfg.Objects.UpstreamRef, nil
}

// GetRefRepoID reads the ref ledger id.
func (m *RefManager) GetRefRepoID(ref string) (string, error) {
	refCfg, err := m.readRefConfig(ref)
	if err != nil {
		return "", err
	}
	if refCfg == nil {
		return "", azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: invalid ref config file")

	}
	return refCfg.Objects.RepoID, nil
}

// GetRefCommit reads the ref commit.
func (m *RefManager) GetRefCommit(ref string) (string, error) {
	refCfg, err := m.readRefConfig(ref)
	if err != nil {
		return "", err
	}
	if refCfg == nil {
		return "", azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: invalid ref config file")
	}
	return refCfg.Objects.Commit, nil
}

// GetCurrentHead gets the current head.
func (m *RefManager) GetCurrentHead() (*azicliwkscommon.HeadInfo, error) {
	cfgHead, err := m.readHeadConfig()
	if err != nil {
		return nil, err
	}
	return azicliwkscommon.NewHeadInfo(cfgHead.Reference.Ref)
}

// GetCurrentHeadRef gets the current head ref.
func (m *RefManager) GetCurrentHeadRef() (string, error) {
	headInfo, err := m.GetCurrentHead()
	if err != nil {
		return "", err
	}
	return headInfo.GetRef(), nil
}

// GetCurrentHeadRepoID gets the current head ledger id.
func (m *RefManager) GetCurrentHeadRepoID() (string, error) {
	headInfo, err := m.GetCurrentHead()
	if err != nil {
		return "", err
	}
	return m.GetRefRepoID(headInfo.GetRef())
}

// GetCurrentHeadCommit gets the current head commit.
func (m *RefManager) GetCurrentHeadCommit() (string, error) {
	headInfo, err := m.GetCurrentHead()
	if err != nil {
		return "", err
	}
	return m.GetRefCommit(headInfo.GetRef())
}

// GetRefInfo gets the ref information.
func (m *RefManager) GetRefInfo(ref string) (*azicliwkscommon.RefInfo, error) {
	if len(ref) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid ref")
	}
	return azicliwkscommon.ConvertStringWithRepoIDToRefInfo(ref)
}

// GetCurrentHeadRefInfo gets the current head ref information.
func (m *RefManager) GetCurrentHeadRefInfo() (*azicliwkscommon.RefInfo, error) {
	headInfo, err := m.GetCurrentHead()
	if err != nil {
		return nil, err
	}
	if headInfo == nil || len(headInfo.GetRef()) == 0 {
		return nil, nil
	}
	return m.GetRefInfo(headInfo.GetRef())
}
