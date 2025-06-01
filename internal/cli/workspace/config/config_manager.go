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
	"errors"
	"fmt"

	"github.com/pelletier/go-toml"

	"github.com/permguard/permguard/internal/cli/common"
	wkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/internal/cli/workspace/persistence"
)

const (
	// hiddenConfigFile represents the hidden config file.
	hiddenConfigFile = "config"
)

// ConfigManager implements the internal manager for the config file.
type ConfigManager struct {
	ctx     *common.CliCommandContext
	persMgr *persistence.PersistenceManager
}

// NewConfigManager creates a new configuration manager.
func NewConfigManager(ctx *common.CliCommandContext, persMgr *persistence.PersistenceManager) (*ConfigManager, error) {
	return &ConfigManager{
		ctx:     ctx,
		persMgr: persMgr,
	}, nil
}

// configFile
func (m *ConfigManager) configFile() string {
	return hiddenConfigFile
}

// readConfig reads the config file.
func (m *ConfigManager) readConfig() (*config, error) {
	var cfg config
	err := m.persMgr.ReadTOMLFile(persistence.PermguardDir, m.configFile(), &cfg)
	return &cfg, err
}

// saveConfig saves the config file.
func (m *ConfigManager) saveConfig(override bool, cfg *config) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return errors.Join(err, errors.New("cli: failed to marshal config"))
	}
	fileName := m.configFile()
	if override {
		_, err = m.persMgr.WriteFile(persistence.PermguardDir, fileName, data, 0644, false)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(persistence.PermguardDir, fileName, data, 0644, false)
	}
	if err != nil {
		return errors.Join(err, fmt.Errorf("cli: failed to write config file %s", fileName))
	}
	return nil
}

// RemoteInfo gets the remote info.
func (m *ConfigManager) RemoteInfo(remote string) (*wkscommon.RemoteInfo, error) {
	remote, err := wkscommon.SanitizeRemote(remote)
	if err != nil {
		return nil, err
	}
	cfg, err := m.readConfig()
	if err != nil {
		return nil, err
	}
	if _, ok := cfg.Remotes[remote]; !ok {
		return nil, fmt.Errorf("cli: remote %s does not exist", remote)
	}
	cfgRemote := cfg.Remotes[remote]
	return wkscommon.NewRemoteInfo(cfgRemote.Server, cfgRemote.ZAPPort, cfgRemote.PAPPort)
}

// LedgerInfo gets the ref info.
func (m *ConfigManager) LedgerInfo(ledgerURI string) (*wkscommon.RefInfo, error) {
	cfg, err := m.readConfig()
	if err != nil {
		return nil, err
	}
	if _, ok := cfg.Ledgers[ledgerURI]; !ok {
		return nil, fmt.Errorf("cli: remote %s does not exist", ledgerURI)
	}
	cfgLedger := cfg.Ledgers[ledgerURI]
	refInfo, err := wkscommon.NewRefInfoFromLedgerName(cfgLedger.Remote, cfgLedger.ZoneID, cfgLedger.LedgerName)
	if err != nil {
		return nil, err
	}
	return wkscommon.BuildRefInfoFromLedgerID(refInfo, cfgLedger.LedgerID)
}

// CheckLedgerIfExists checks if a ledger exists.
func (m *ConfigManager) CheckLedgerIfExists(ledgerURI string) bool {
	ledgerURI, _ = wkscommon.SanitizeLedger(ledgerURI)
	cfg, err := m.readConfig()
	if err != nil {
		return false
	}
	if _, ok := cfg.Ledgers[ledgerURI]; !ok {
		return false
	}
	return true
}
