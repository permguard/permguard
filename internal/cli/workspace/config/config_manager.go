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

package config

import (
	"fmt"

	"github.com/pelletier/go-toml"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// hiddenConfigFile represents the hidden config file.
	hiddenConfigFile = "config"
)

// ConfigManager implements the internal manager for the config file.
type ConfigManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
}

// NewConfigManager creates a new configuration manager.
func NewConfigManager(ctx *aziclicommon.CliCommandContext, persMgr *azicliwkspers.PersistenceManager) (*ConfigManager, error) {
	return &ConfigManager{
		ctx:     ctx,
		persMgr: persMgr,
	}, nil
}

// getConfigFile
func (m *ConfigManager) getConfigFile() string {
	return hiddenConfigFile
}

// readConfig reads the config file.
func (m *ConfigManager) readConfig() (*config, error) {
	var config config
	err := m.persMgr.ReadTOMLFile(azicliwkspers.PermguardDir, m.getConfigFile(), &config)
	return &config, err
}

// saveConfig saves the config file.
func (m *ConfigManager) saveConfig(override bool, cfg *config) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliFileOperation, "failed to marshal config", err)
	}
	fileName := m.getConfigFile()
	if override {
		_, err = m.persMgr.WriteFile(azicliwkspers.PermguardDir, fileName, data, 0644, false)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(azicliwkspers.PermguardDir, fileName, data, 0644, false)
	}
	if err != nil {
		return azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliFileOperation, fmt.Sprintf("failed to write config file %s", fileName), err)
	}
	return nil
}

// GetRemoteInfo gets the remote info.
func (m *ConfigManager) GetRemoteInfo(remote string) (*azicliwkscommon.RemoteInfo, error) {
	remote, err := azicliwkscommon.SanitizeRemote(remote)
	if err != nil {
		return nil, err
	}
	cfg, err := m.readConfig()
	if err != nil {
		return nil, err
	}
	if _, ok := cfg.Remotes[remote]; !ok {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliRecordNotFound, fmt.Sprintf("remote %s does not exist", remote))
	}
	cfgRemote := cfg.Remotes[remote]
	return azicliwkscommon.NewRemoteInfo(cfgRemote.Server, cfgRemote.ZAPPort, cfgRemote.PAPPort)
}

// GetLedgerInfo gets the ref info.
func (m *ConfigManager) GetLedgerInfo(ledgerURI string) (*azicliwkscommon.RefInfo, error) {
	cfg, err := m.readConfig()
	if err != nil {
		return nil, err
	}
	if _, ok := cfg.Ledgers[ledgerURI]; !ok {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliRecordNotFound, fmt.Sprintf("remote %s does not exist", ledgerURI))
	}
	cfgLedger := cfg.Ledgers[ledgerURI]
	refInfo, err := azicliwkscommon.NewRefInfoFromLedgerName(cfgLedger.Remote, cfgLedger.ZoneID, cfgLedger.LedgerName)
	if err != nil {
		return nil, err
	}
	return azicliwkscommon.BuildRefInfoFromLedgerID(refInfo, cfgLedger.LedgerID)
}

// CheckLedgerIfExists checks if a ledger exists.
func (m *ConfigManager) CheckLedgerIfExists(ledgerURI string) bool {
	ledgerURI, _ = azicliwkscommon.SanitizeLedger(ledgerURI)
	cfg, err := m.readConfig()
	if err != nil {
		return false
	}
	if _, ok := cfg.Ledgers[ledgerURI]; !ok {
		return false
	}
	return true
}
