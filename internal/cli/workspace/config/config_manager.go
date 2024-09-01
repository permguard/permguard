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
	azcrypto "github.com/permguard/permguard/pkg/extensions/crypto"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
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
	err := m.persMgr.ReadTOMLFile(true, m.getConfigFile(), &config)
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
		_, err = m.persMgr.WriteFile(true, fileName, data, 0644)
	} else {
		_, err = m.persMgr.WriteFileIfNotExists(true, fileName, data, 0644)
	}
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: failed to write config file %s", fileName))
	}
	return nil
}

// Initialize initializes the config resources.
func (m *ConfigManager) Initialize() error {
	config := Config{
		Core: CoreConfig{
			ClientVersion: m.ctx.GetClientVersion(),
		},
		Remotes:      map[string]RemoteConfig{},
		Repositories: map[string]RepositoryConfig{},
	}
	return m.saveConfig(false, &config)
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

// AddRemote adds a remote.
func (m *ConfigManager) AddRemote(remote string, server string, aap int, pap int, output map[string]any, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	remote, err := azicliwksvals.SanitizeRemote(remote)
	if err != nil {
		return output, err
	}
	cfg, err := m.readConfig()
	if err != nil {
		return output, err
	}
	for rmt := range cfg.Remotes {
		if remote == rmt {
			return output, azerrors.WrapSystemError(azerrors.ErrCliRecordExists, fmt.Sprintf("cli: remote %s already exists", remote))
		}
	}
	cfgRemote := RemoteConfig{
		Server: server,
		AAP:    aap,
		PAP:    pap,
	}
	cfg.Remotes[remote] = cfgRemote
	m.saveConfig(true, cfg)
	if m.ctx.IsTerminalOutput() {
		output = out(nil, "remotes", cfgRemote, nil)
	} else {
		remotes := []interface{}{}
		remoteObj := map[string]any{
			"remote": remote,
			"server": cfgRemote.Server,
			"aap":    cfgRemote.AAP,
			"pap":    cfgRemote.PAP,
		}
		remotes = append(remotes, remoteObj)
		output = out(output, "remote", remotes, nil)
	}
	return output, nil
}

// RemoveRemote removes a remote.
func (m *ConfigManager) RemoveRemote(remote string, output map[string]any, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	remote, err := azicliwksvals.SanitizeRemote(remote)
	if err != nil {
		return output, err
	}
	cfg, err := m.readConfig()
	if err != nil {
		return output, err
	}
	if _, ok := cfg.Remotes[remote]; !ok {
		return output, azerrors.WrapSystemError(azerrors.ErrCliRecordNotFound, fmt.Sprintf("cli: remote %s does not exist", remote))
	}
	cfgRemote := cfg.Remotes[remote]
	if m.ctx.IsTerminalOutput() {
		output = out(nil, "remote", cfgRemote, nil)
	} else {
		remotes := []interface{}{}
		remoteObj := map[string]any{
			"remote": remote,
			"server": cfgRemote.Server,
			"aap":    cfgRemote.AAP,
			"pap":    cfgRemote.PAP,
		}
		remotes = append(remotes, remoteObj)
		output = out(output, "remotes", remotes, nil)
	}
	delete(cfg.Remotes, remote)
	m.saveConfig(true, cfg)
	return output, nil
}

// ListRemotes lists the remotes.
func (m *ConfigManager) ListRemotes(output map[string]any, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	cfg, err := m.readConfig()
	if err != nil {
		return output, err
	}
	if m.ctx.IsTerminalOutput() {
		remotes := []string{}
		for cfgRemote := range cfg.Remotes {
			remotes = append(remotes, cfgRemote)
		}
		if len(remotes) > 0 {
			output = out(nil, "remotes", remotes, nil)
		}
	} else {
		remotes := []interface{}{}
		for cfgRemote := range cfg.Remotes {
			remoteObj := map[string]any{
				"remote": cfgRemote,
				"server": cfg.Remotes[cfgRemote].Server,
				"aap":    cfg.Remotes[cfgRemote].AAP,
				"pap":    cfg.Remotes[cfgRemote].PAP,
			}
			remotes = append(remotes, remoteObj)
		}
		output = out(output, "remotes", remotes, nil)
	}
	return output, nil
}

// AddRepo adds a repo.
func (m *ConfigManager) AddRepo(remote string, accountID int64, repo string, ref string, refID string, output map[string]any, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	cfg, err := m.readConfig()
	if err != nil {
		return output, err
	}
	var cfgRepo RepositoryConfig
	exists := false
	for repo := range cfg.Repositories {
		if ref == repo {
			cfgRepo = cfg.Repositories[repo]
			exists = true
		}
	}
	if !exists {
		cfgRepo = RepositoryConfig{
			Remote: remote,
			Refs:   refID,
		}
		cfg.Repositories[refID] = cfgRepo
		m.saveConfig(true, cfg)
	}
	if m.ctx.IsTerminalOutput() {
		output = out(nil, "repo", refID, nil)
	} else {
		remotes := []interface{}{}
		remoteObj := map[string]any{
			"remote": remote,
			"refs":   cfgRepo.Refs,
		}
		remotes = append(remotes, remoteObj)
		output = out(output, "repos", remotes, nil)
	}
	return output, nil
}

// ListRepos lists the repos.
func (m *ConfigManager) ListRepos(refRepo string, output map[string]any, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	cfg, err := m.readConfig()
	if err != nil {
		return output, err
	}
	if m.ctx.IsTerminalOutput() {
		repos := []string{}
		for cfgRepo := range cfg.Repositories {
			isActive := refRepo == cfgRepo
			cfgRepoTxt := cfgRepo
			if isActive {
				cfgRepoTxt = fmt.Sprintf("*%s", cfgRepo)
			}
			repos = append(repos, cfgRepoTxt)
		}
		if len(repos) > 0 {
			output = out(nil, "repos", repos, nil)
		}
	} else {
		repos := []interface{}{}
		for cfgRepo := range cfg.Repositories {
			isActive := refRepo == cfgRepo
			repoObj := map[string]any{
				"remote":  cfg.Repositories[cfgRepo].Remote,
				"repo": cfgRepo,
				"refs": cfg.Repositories[cfgRepo].Refs,
				"active": isActive,
			}
			repos = append(repos, repoObj)
		}
		output = out(output, "repos", repos, nil)
	}
	return output, nil
}
