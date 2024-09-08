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

package workspace

import (
	"fmt"
	"path/filepath"

	"github.com/gofrs/flock"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscfg "github.com/permguard/permguard/internal/cli/workspace/config"
	azicliwkscosp "github.com/permguard/permguard/internal/cli/workspace/cosp"
	azicliwkslogs "github.com/permguard/permguard/internal/cli/workspace/logs"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azicliwksrefs "github.com/permguard/permguard/internal/cli/workspace/refs"
	azicliwksremotesrv "github.com/permguard/permguard/internal/cli/workspace/remoteserver"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlang "github.com/permguard/permguard/pkg/core/languages"
)

const (
	// hiddenDir represents the permguard's hidden directory.
	hiddenDir = ".permguard"
	// hiddenLockFile represents the permguard's lock file.
	hiddenLockFile = "permguard.lock"
)

// WorkspaceManager implements the internal manager to manage the .permguard directory.
type WorkspaceManager struct {
	ctx       *aziclicommon.CliCommandContext
	homeDir   string
	langFct   azlang.LanguageFactory
	persMgr   *azicliwkspers.PersistenceManager
	rmSrvtMgr *azicliwksremotesrv.RemoteServerManager
	cfgMgr    *azicliwkscfg.ConfigManager
	logsMgr   *azicliwkslogs.LogsManager
	rfsMgr    *azicliwksrefs.RefsManager
	cospMgr   *azicliwkscosp.COSPManager
}

// NewInternalManager creates a new internal manager.
func NewInternalManager(ctx *aziclicommon.CliCommandContext, langFct azlang.LanguageFactory) *WorkspaceManager {
	homeDir := ctx.GetWorkDir()
	persMgr := azicliwkspers.NewPersistenceManager(homeDir, hiddenDir, ctx)
	return &WorkspaceManager{
		homeDir:   homeDir,
		ctx:       ctx,
		langFct:   langFct,
		persMgr:   persMgr,
		rmSrvtMgr: azicliwksremotesrv.NewRemoteServerManager(ctx),
		cfgMgr:    azicliwkscfg.NewConfigManager(ctx, persMgr),
		logsMgr:   azicliwkslogs.NewLogsManager(ctx, persMgr),
		rfsMgr:    azicliwksrefs.NewRefsManager(ctx, persMgr),
		cospMgr:   azicliwkscosp.NewPlansManager(ctx, persMgr),
	}
}

// getHomeHiddenDir returns the home directory.
func (m *WorkspaceManager) getHomeDir() string {
	return m.homeDir
}

// getHomeHiddenDir returns the home hidden directory.
func (m *WorkspaceManager) getHomeHiddenDir() string {
	return filepath.Join(m.homeDir, hiddenDir)
}

// getLockFile returns the lock file.
func (m *WorkspaceManager) getLockFile() string {
	return filepath.Join(m.getHomeHiddenDir(), hiddenLockFile)
}

// isWorkspaceDir checks if the directory is a workspace directory.
func (m *WorkspaceManager) isWorkspaceDir() bool {
	isValid, _ := m.persMgr.CheckFileIfExists(azicliwkspers.PermGuardDir, "")
	return isValid
}

// tryLock tries to lock the workspace.
func (m *WorkspaceManager) tryLock() (*flock.Flock, error) {
	lockFile := m.getLockFile()
	m.persMgr.CreateFileIfNotExists(azicliwkspers.PermGuardDir, lockFile)
	fileLock := flock.New(lockFile)
	lock, err := fileLock.TryLock()
	if !lock || err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: could not acquire the lock, another process is using it %s", m.getLockFile()))
	}
	return fileLock, nil
}
