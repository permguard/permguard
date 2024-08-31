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

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
)

const (
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
func (c *ConfigManager) getConfigFile() string {
	return hiddenConfigFile
}

// readConfig reads the configuration file.
func (c *ConfigManager) readConfig() (*Config, error) {
	var config Config
	err := c.persMgr.ReadTOMLFile(true, c.getConfigFile(), &config)
	return &config, err
}

// saveConfig saves the configuration file.
func (c *ConfigManager) saveConfig(override bool, cfg *Config) error {
	data, err := toml.Marshal(cfg)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to marshal config")
	}
	fileName := c.getConfigFile()
	if override {
		_, err = c.persMgr.WriteFile(true, fileName, data, 0644)
	} else {
		_, err = c.persMgr.WriteFileIfNotExists(true, fileName, data, 0644)
	}
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: failed to write config file %s", fileName))
	}
	return nil
}

// Initialize initializes the config resources.
func (c *ConfigManager) Initialize() error {
	config := Config{
		Core: CoreConfig{
			ClientVersion: c.ctx.GetClientVersion(),
		},
		Remotes:      map[string]RemoteConfig{},
		Repositories: map[string]RepositoryConfig{},
	}
	return c.saveConfig(false, &config)
}

// AddRemote adds a remote.
func (c *ConfigManager) AddRemote(remote string, server string, aap int, pap int, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	cfg, err := c.readConfig()
	if err != nil {
		return nil, err
	}
	for rmt := range cfg.Remotes {
		if remote == rmt {
			return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: remote %s already exists", remote))
		}
	}
	cfg.Remotes[remote] = RemoteConfig{
		Server: server,
		AAP:    aap,
		PAP:    pap,
	}
	c.saveConfig(true, cfg)
	output := out(nil, "remote-add", fmt.Sprintf("Added remote %s", remote), nil)
	return output, nil
}

// RemoveRemote removes a remote.
func (c *ConfigManager) RemoveRemote(remote string, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	cfg, err := c.readConfig()
	if err != nil {
		return nil, err
	}
	if _, ok := cfg.Remotes[remote]; !ok {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: remote %s does not exist", remote))
	}
	delete(cfg.Remotes, remote)
	c.saveConfig(true, cfg)
	output := out(nil, "remote-remove", fmt.Sprintf("Removed remote %s", remote), nil)
	return output, nil
}

// ListRemotes lists the remotes.
func (c *ConfigManager) ListRemotes(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	cfg, err := c.readConfig()
	if err != nil {
		return nil, err
	}
	remotes := []string{}
	for remote := range cfg.Remotes {
		remotes = append(remotes, remote)
	}
	output := out(nil, "remote-list", remotes, nil)
	return output, nil
}
