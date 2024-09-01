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

// CheckoutHead checks out the head.
func (m *RefsManager) CheckoutHead(remote string, accountID int64, repo string, refHead string, output map[string]any, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	refIDStr := fmt.Sprintf("%s/%d/%s", remote, accountID, repo)
	refID := azcrypto.ComputeStringSHA1(refIDStr)
	refPath := filepath.Join(hiddenRefsDir, refID)
	refCfg := RefsConfig{
		Objects: RefsObjectsConfig{
			Commit: refHead,
		},
	}
	err := m.saveConfig(refPath, true, &refCfg)
	if err != nil {
		return nil, err
	}
	headCfg := HeadConfig{
		Head: HeadRefsConfig{
			Remote:    remote,
			AccountID: accountID,
			Repo:      repo,
			Refs:      refID,
		},
	}
	headFile := m.getHeadFile()
	err = m.saveConfig(headFile, true, &headCfg)
	if err != nil {
		return nil, err
	}
	if m.ctx.IsTerminalOutput() {
		output = out(nil, "head", fmt.Sprintf("refs/%s", refID), nil)
	} else {
		remotes := []interface{}{}
		remoteObj := map[string]any{
			"remote":    headCfg.Head.Remote,
			"accountid": headCfg.Head.AccountID,
			"repo":      headCfg.Head.Repo,
			"refs":      headCfg.Head.Refs,
		}
		remotes = append(remotes, remoteObj)
		output = out(output, "head", remotes, nil)
	}
	return output, nil
}
