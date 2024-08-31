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

package logs

import (
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
)

const (
	hiddenLogsDir = "logs"
)

// LogsManager implements the internal manager for the logs file.
type LogsManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
}

// NewLogsManager creates a new logsuration manager.
func NewLogsManager(ctx *aziclicommon.CliCommandContext, persMgr *azicliwkspers.PersistenceManager) *LogsManager {
	return &LogsManager{
		ctx:     ctx,
		persMgr: persMgr,
	}
}

// GetLogsDir returns the logs directory.
func (c *LogsManager) GetLogsDir() string {
	return hiddenLogsDir
}

// Initalize the logs resources.
func (c *LogsManager) Initalize() error {
	_, err := c.persMgr.CreateDirIfNotExists(true, c.GetLogsDir())
	return err
}
