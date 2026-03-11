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
	azwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/internal/cli/workspace/persistence"
)

const (
	// hiddenConfigFile represents the hidden config file.
	hiddenConfigFile = "config"
)

// Manager implements the internal manager for the config file.
type Manager struct {
	ctx     *common.CliCommandContext
	persMgr *persistence.Manager
}

// NewManager creates a new configuration manager.
func NewManager(ctx *common.CliCommandContext, persMgr *persistence.Manager) (*Manager, error) {
	return &Manager{
		ctx:     ctx,
		persMgr: persMgr,
	}, nil
}

// configFile
func (m *Manager) configFile() string {
	return hiddenConfigFile
}

// readConfig reads the config file.
func (m *Manager) readConfig() (*config, error) {
	var cfg config
	err := m.persMgr.ReadTOMLFile(persistence.PermguardDir, m.configFile(), &cfg)
	return &cfg, err
}

// saveConfig saves the config file.
func (m *Manager) saveConfig(override bool, cfg *config) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return errors.Join(err, errors.New("cli: failed to marshal config"))
	}
	fileName := m.configFile()
	if override {
		_, err = m.persMgr.WriteFile(persistence.PermguardDir, fileName, data, 0o644, false)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(persistence.PermguardDir, fileName, data, 0o644, false)
	}
	if err != nil {
		return errors.Join(err, fmt.Errorf("cli: failed to write config file %s", fileName))
	}
	return nil
}

// RemoteInfo gets the remote info.
func (m *Manager) RemoteInfo(remote string) (*azwkscommon.RemoteInfo, error) {
	remote, err := azwkscommon.SanitizeRemote(remote)
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
	return azwkscommon.NewRemoteInfo(cfgRemote.Server, cfgRemote.ZAPPort, cfgRemote.PAPPort)
}

// LedgerInfo gets the ref info.
func (m *Manager) LedgerInfo(ledgerURI string) (*azwkscommon.RefInfo, error) {
	cfg, err := m.readConfig()
	if err != nil {
		return nil, err
	}
	if _, ok := cfg.Ledgers[ledgerURI]; !ok {
		return nil, fmt.Errorf("cli: remote %s does not exist", ledgerURI)
	}
	cfgLedger := cfg.Ledgers[ledgerURI]
	refInfo, err := azwkscommon.NewRefInfoFromLedgerName(cfgLedger.Remote, cfgLedger.ZoneID, cfgLedger.LedgerName)
	if err != nil {
		return nil, err
	}
	return azwkscommon.BuildRefInfoFromLedgerID(refInfo, cfgLedger.LedgerID)
}

// AuthstarMaxObjectSize returns the configured authstar maximum object size in bytes, or 0 if not set.
func (m *Manager) AuthstarMaxObjectSize() int {
	cfg, err := m.readConfig()
	if err != nil {
		return 0
	}
	return cfg.Core.AuthstarMaxObjectSize
}

// SetAuthstarMaxObjectSize sets the authstar maximum object size in bytes.
func (m *Manager) SetAuthstarMaxObjectSize(size int) error {
	if size <= 0 {
		return errors.New("cli: authstar-max-object-size must be a positive integer")
	}
	cfg, err := m.readConfig()
	if err != nil {
		return err
	}
	cfg.Core.AuthstarMaxObjectSize = size
	return m.saveConfig(true, cfg)
}

// CheckLedgerIfExists checks if a ledger exists.
func (m *Manager) CheckLedgerIfExists(ledgerURI string) bool {
	ledgerURI, _ = azwkscommon.SanitizeLedger(ledgerURI)
	cfg, err := m.readConfig()
	if err != nil {
		return false
	}
	if _, ok := cfg.Ledgers[ledgerURI]; !ok {
		return false
	}
	return true
}
