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
	"fmt"
	"strings"
	"time"

	"path/filepath"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azvalidators "github.com/permguard/permguard/pkg/agents/storage/validators"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
)

type LogAction string

const (
	// hiddenLogsDir represents the hidden logs directory.
	hiddenLogsDir = "logs"
	// LogActionCheckout represents the checkout action.
	LogActionCheckout = "checkout"
	// LogActionPull represents the pull action.
	LogActionPull = "pull"
	// LogActionPush represents the push action.
	LogActionPush = "push"
)

// LogsManager implements the internal manager for the logs file.
type LogsManager struct {
	ctx     *aziclicommon.CliCommandContext
	persMgr *azicliwkspers.PersistenceManager
}

// NewLogsManager creates a new logsuration manager.
func NewLogsManager(ctx *aziclicommon.CliCommandContext, persMgr *azicliwkspers.PersistenceManager) (*LogsManager, error) {
	return &LogsManager{
		ctx:     ctx,
		persMgr: persMgr,
	}, nil
}

// getLogsDir returns the logs directory.
func (c *LogsManager) getLogsDir() string {
	return hiddenLogsDir
}

// Log an entry
func (c *LogsManager) Log(remote string, refs string, origin string, target string, action LogAction, actionStatus bool, actionDetail string) (bool, error) {
	if strings.TrimSpace(remote) == "" {
		return false, fmt.Errorf("Invalid action")
	}
	if strings.TrimSpace(refs) == "" {
		return false, fmt.Errorf("Invalid action")
	}
	if err := azvalidators.ValidateSHA256("logs", origin); err != nil {
		return false, fmt.Errorf("Invalid origin sha256")
	}
	if err := azvalidators.ValidateSHA256("logs", target); err != nil {
		return false, fmt.Errorf("Invalid target sha256")
	}
	if strings.TrimSpace(string(action)) == "" {
		return false, fmt.Errorf("Invalid action")
	}
	if strings.TrimSpace(string(actionDetail)) == "" {
		return false, fmt.Errorf("Invalid action")
	}
	logDir := filepath.Join(c.getLogsDir(), remote)
	_, err := c.persMgr.CreateDirIfNotExists(azicliwkspers.PermguardDir, logDir)
	if err != nil {
		return false, err
	}
	logFile := filepath.Join(logDir, refs)
	_, err = c.persMgr.CreateFileIfNotExists(azicliwkspers.PermguardDir, logFile)
	if err != nil {
		return false, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	status := "completed"
	if !actionStatus {
		status = "failed"
	}
	logLine := fmt.Sprintf("%s %s %s %s %s %s\n", origin, target, timestamp, strings.ToLower(string(action)), status, strings.ToLower(actionDetail))
	return c.persMgr.AppendToFile(azicliwkspers.PermguardDir, logFile, []byte(logLine), false)
}
