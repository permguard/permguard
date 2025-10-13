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
	"errors"
	"fmt"
	"path/filepath"

	"github.com/pelletier/go-toml"

	"github.com/permguard/permguard/internal/cli/common"
	wkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/internal/cli/workspace/persistence"
)

const (
	// hiddenRefsDir represents the hidden refs directory.
	hiddenRefsDir = "refs"
	// hiddenHeadFile represents the hidden head file.
	hiddenHeadFile = "HEAD"
)

// RefManager implements the internal manager for the ref files.
type RefManager struct {
	ctx     *common.CliCommandContext
	persMgr *persistence.PersistenceManager
}

// NewRefManager creates a new refuration manager.
func NewRefManager(ctx *common.CliCommandContext, persMgr *persistence.PersistenceManager) (*RefManager, error) {
	return &RefManager{
		ctx:     ctx,
		persMgr: persMgr,
	}, nil
}

// refsDir returns the refs directory.
func (m *RefManager) refsDir() string {
	return hiddenRefsDir
}

// headFile returns the head file.
func (m *RefManager) headFile() string {
	return hiddenHeadFile
}

// refFile returns the ref file.
func (m *RefManager) refFile(ref string) (string, error) {
	refInfo, err := wkscommon.ConvertStringWithLedgerIDToRefInfo(ref)
	if err != nil {
		return "", err
	}
	return filepath.Join(hiddenRefsDir, refInfo.SourceType(), refInfo.Remote(), fmt.Sprintf("%d", refInfo.ZoneID()), refInfo.LedgerID()), nil
}

// ensureRefFileExists ensures the ref file exists.
func (m *RefManager) ensureRefFileExists(ref string) error {
	refFile, err := m.refFile(ref)
	if err != nil {
		return err
	}
	_, err = m.persMgr.CreateFileIfNotExists(persistence.PermguardDir, refFile)
	if err != nil {
		return err
	}
	return err
}

// GenerateRef generates the ref.
func (m *RefManager) GenerateRef(remote string, zoneID int64, ledgerID string) string {
	refInfo, _ := wkscommon.NewRefInfoFromLedgerName(remote, zoneID, ledgerID)
	ref := wkscommon.ConvertRefInfoToString(refInfo)
	return ref
}

// saveConfig saves the config file.
func (m *RefManager) saveConfig(name string, override bool, cfg any) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return errors.Join(err, errors.New("cli: failed to marshal config"))
	}
	if override {
		_, err = m.persMgr.WriteFile(persistence.PermguardDir, name, data, 0o644, false)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(persistence.PermguardDir, name, data, 0o644, false)
	}
	if err != nil {
		return errors.Join(err, fmt.Errorf("cli: failed to write config file %s", name))
	}
	return nil
}

// SaveHeadConfig saves the head config file.
func (m *RefManager) SaveHeadConfig(ref string) error {
	headFile := m.headFile()
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
	err := m.persMgr.ReadTOMLFile(persistence.PermguardDir, m.headFile(), &config)
	return &config, err
}

// SaveRefConfig saves the ref configuration.
func (m *RefManager) SaveRefConfig(ledgerID string, ref string, commit string) error {
	return m.SaveRefWithRemoteConfig(ledgerID, ref, "", commit)
}

// SaveRefWithRemoteConfig saves the ref with remote configuration.
func (m *RefManager) SaveRefWithRemoteConfig(ledgerID string, ref, upstreamRef string, commit string) error {
	err := m.ensureRefFileExists(ref)
	if err != nil {
		return err
	}
	refPath, err := m.refFile(ref)
	if err != nil {
		return err
	}
	refCfg := refConfig{
		Objects: refObjectsConfig{
			UpstreamRef: upstreamRef,
			LedgerID:    ledgerID,
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
	refPath, err := m.refFile(ref)
	if err != nil {
		return nil, err
	}
	var config refConfig
	err = m.persMgr.ReadTOMLFile(persistence.PermguardDir, refPath, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// RefUpstreamRef reads the ref upstream ref.
func (m *RefManager) RefUpstreamRef(ref string) (string, error) {
	refCfg, err := m.readRefConfig(ref)
	if err != nil {
		return "", err
	}
	if refCfg == nil {
		return "", errors.Join(err, errors.New("cli: invalid ref config file"))
	}
	return refCfg.Objects.UpstreamRef, nil
}

// RefLedgerID reads the ref ledger id.
func (m *RefManager) RefLedgerID(ref string) (string, error) {
	refCfg, err := m.readRefConfig(ref)
	if err != nil {
		return "", err
	}
	if refCfg == nil {
		return "", errors.Join(err, errors.New("cli: invalid ref config file"))
	}
	return refCfg.Objects.LedgerID, nil
}

// RefCommit reads the ref commit.
func (m *RefManager) RefCommit(ref string) (string, error) {
	refCfg, err := m.readRefConfig(ref)
	if err != nil {
		return "", err
	}
	if refCfg == nil {
		return "", errors.Join(err, errors.New("cli: invalid ref config file"))
	}
	return refCfg.Objects.Commit, nil
}

// CurrentHead gets the current head.
func (m *RefManager) CurrentHead() (*wkscommon.HeadInfo, error) {
	cfgHead, err := m.readHeadConfig()
	if err != nil {
		return nil, err
	}
	return wkscommon.NewHeadInfo(cfgHead.Reference.Ref)
}

// CurrentHeadRef gets the current head ref.
func (m *RefManager) CurrentHeadRef() (string, error) {
	headInfo, err := m.CurrentHead()
	if err != nil {
		return "", err
	}
	return headInfo.Ref(), nil
}

// CurrentHeadLedgerID gets the current head ledger id.
func (m *RefManager) CurrentHeadLedgerID() (string, error) {
	headInfo, err := m.CurrentHead()
	if err != nil {
		return "", err
	}
	return m.RefLedgerID(headInfo.Ref())
}

// CurrentHeadCommit gets the current head commit.
func (m *RefManager) CurrentHeadCommit() (string, error) {
	headInfo, err := m.CurrentHead()
	if err != nil {
		return "", err
	}
	return m.RefCommit(headInfo.Ref())
}

// RefInfo gets the ref information.
func (m *RefManager) RefInfo(ref string) (*wkscommon.RefInfo, error) {
	if len(ref) == 0 {
		return nil, errors.New("cli: invalid ref")
	}
	return wkscommon.ConvertStringWithLedgerIDToRefInfo(ref)
}

// CurrentHeadRefInfo gets the current head ref information.
func (m *RefManager) CurrentHeadRefInfo() (*wkscommon.RefInfo, error) {
	headInfo, err := m.CurrentHead()
	if err != nil {
		return nil, err
	}
	if headInfo == nil || len(headInfo.Ref()) == 0 {
		return nil, nil
	}
	return m.RefInfo(headInfo.Ref())
}
