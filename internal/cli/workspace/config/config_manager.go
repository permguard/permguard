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

// Initialize initializes the config resources.
func (c *ConfigManager) Initialize() error {
	config := Config{
		Core: CoreConfig{
			ClientVersion: c.ctx.GetClientVersion(),
		},
		Remotes: map[string]RemoteConfig{},
		Repositories: map[string]RepositoryConfig{},
	}
	data, err := toml.Marshal(config)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to marshal config")
	}
	fileName := c.getConfigFile()
	_, err = c.persMgr.WriteFileIfNotExists(true, fileName, data, 0644)
	if err != nil {
		return azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: failed to write config file %s", fileName))
	}
	return nil
}
