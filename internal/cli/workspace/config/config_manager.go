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
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azicliwksvals "github.com/permguard/permguard/internal/cli/workspace/validators"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// hiddenConfigFile represents the hidden configuration file.
	hiddenConfigFile = "config"
)

// ConfigManager implements the internal manager for the config file.
type ConfigManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
}

// NewConfigManager creates a new configuration manager.
func NewConfigManager(ctx *aziclicommon.CliCommandContext, persMgr *azicliwkspers.PersistenceManager) *ConfigManager {
	return &ConfigManager{
		ctx:     ctx,
		persMgr: persMgr,
	}
}

// getConfigFile
func (m *ConfigManager) getConfigFile() string {
	return hiddenConfigFile
}

// readConfig reads the configuration file.
func (m *ConfigManager) readConfig() (*Config, error) {
	var config Config
	err := m.persMgr.ReadTOMLFile(azicliwkspers.PermGuardDir, m.getConfigFile(), &config)
	return &config, err
}

// saveConfig saves the configuration file.
func (m *ConfigManager) saveConfig(override bool, cfg *Config) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to marshal config")
	}
	fileName := m.getConfigFile()
	if override {
		_, err = m.persMgr.WriteFile(azicliwkspers.PermGuardDir, fileName, data, 0644, false)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(azicliwkspers.PermGuardDir, fileName, data, 0644, false)
	}
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: failed to write config file %s", fileName))
	}
	return nil
}

// GetLanguage gets the language.
func (m *ConfigManager) GetLanguage() (string, error) {
	cfg, err := m.readConfig()
	if err != nil {
		return "", err
	}
	return cfg.Core.Language, nil
}

// GetRemote gets a remote.
func (m *ConfigManager) GetRemote(remote string) (*RemoteConfig, error) {
	remote, err := azicliwksvals.SanitizeRemote(remote)
	if err != nil {
		return nil, err
	}
	cfg, err := m.readConfig()
	if err != nil {
		return nil, err
	}
	if _, ok := cfg.Remotes[remote]; !ok {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliRecordNotFound, fmt.Sprintf("cli: remote %s does not exist", remote))
	}
	cfgRemote := cfg.Remotes[remote]
	return &cfgRemote, nil
}

// GetRepo gets a repo.
func (m *ConfigManager) GetRepo(repoURI string) (*RepositoryConfig, error) {
	repoURI, err := azicliwksvals.SanitizeRepo(repoURI)
	if err != nil {
		return nil, err
	}
	cfg, err := m.readConfig()
	if err != nil {
		return nil, err
	}
	if _, ok := cfg.Repositories[repoURI]; !ok {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliRecordNotFound, fmt.Sprintf("cli: repo %s does not exist", repoURI))
	}
	cfgRepo := cfg.Repositories[repoURI]
	return &cfgRepo, nil
}
