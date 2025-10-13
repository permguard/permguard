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
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/permguard/permguard/internal/cli/common"
	wkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/internal/cli/workspace/persistence"
	"github.com/permguard/permguard/pkg/core/validators"
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
	ctx     *common.CliCommandContext
	persMgr *persistence.PersistenceManager
}

// NewLogsManager creates a new logsuration manager.
func NewLogsManager(ctx *common.CliCommandContext, persMgr *persistence.PersistenceManager) (*LogsManager, error) {
	return &LogsManager{
		ctx:     ctx,
		persMgr: persMgr,
	}, nil
}

// logsDir returns the logs directory.
func (c *LogsManager) logsDir() string {
	return hiddenLogsDir
}

// Log an entry
func (c *LogsManager) Log(refInfo *wkscommon.RefInfo, origin string, target string, action LogAction, actionStatus bool, actionDetail string) (bool, error) {
	if refInfo == nil {
		return false, errors.New("invalid ref info")
	}
	if err := validators.ValidateSHA256("logs", origin); err != nil {
		return false, errors.New("invalid origin sha256")
	}
	if err := validators.ValidateSHA256("logs", target); err != nil {
		return false, errors.New("invalid target sha256")
	}
	if strings.TrimSpace(string(action)) == "" {
		return false, errors.New("invalid action")
	}
	if strings.TrimSpace(string(actionDetail)) == "" {
		return false, errors.New("invalid action")
	}
	logDir := refInfo.LedgerFilePath(false)
	_, err := c.persMgr.CreateDirIfNotExists(persistence.PermguardDir, logDir)
	if err != nil {
		return false, err
	}
	logFile := filepath.Join(c.logsDir(), logDir, refInfo.LedgerID())
	_, err = c.persMgr.CreateFileIfNotExists(persistence.PermguardDir, logFile)
	if err != nil {
		return false, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	status := "completed"
	if !actionStatus {
		status = "failed"
	}
	logLine := fmt.Sprintf("%s %s %s %s %s %s\n", origin, target, timestamp, strings.ToLower(string(action)), status, strings.ToLower(actionDetail))
	return c.persMgr.AppendToFile(persistence.PermguardDir, logFile, []byte(logLine), false)
}
