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
	azicliwkslogs "github.com/permguard/permguard/internal/cli/workspace/logs"
	azicliwksobjs "github.com/permguard/permguard/internal/cli/workspace/objects"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azicliwksplans "github.com/permguard/permguard/internal/cli/workspace/plans"
	azicliwksrefs "github.com/permguard/permguard/internal/cli/workspace/refs"
	azicliwksremotesrv "github.com/permguard/permguard/internal/cli/workspace/remoteserver"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
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
	persMgr   *azicliwkspers.PersistenceManager
	rmSrvtMgr *azicliwksremotesrv.RemoteServerManager
	cfgMgr    *azicliwkscfg.ConfigManager
	logsMgr   *azicliwkslogs.LogsManager
	rfsMgr    *azicliwksrefs.RefsManager
	objsMgr   *azicliwksobjs.ObjectsManager
	plansMgr  *azicliwksplans.PlansManager
}

// NewInternalManager creates a new internal manager.
func NewInternalManager(ctx *aziclicommon.CliCommandContext) *WorkspaceManager {
	hdnDir := filepath.Join(ctx.GetWorkDir(), hiddenDir)
	persMgr := azicliwkspers.NewPersistenceManager(hdnDir, ctx)
	return &WorkspaceManager{
		homeDir:   hdnDir,
		ctx:       ctx,
		persMgr:   persMgr,
		rmSrvtMgr: azicliwksremotesrv.NewRemoteServerManager(ctx),
		cfgMgr:    azicliwkscfg.NewConfigManager(ctx, persMgr),
		logsMgr:   azicliwkslogs.NewLogsManager(ctx, persMgr),
		rfsMgr:    azicliwksrefs.NewRefsManager(ctx, persMgr),
		objsMgr:   azicliwksobjs.NewObjectsManager(ctx, persMgr),
		plansMgr:  azicliwksplans.NewPlansManager(ctx, persMgr),
	}
}

// getHomeDir returns the home directory.
func (m *WorkspaceManager) getHomeDir() string {
	return m.homeDir
}

// getLockFile returns the lock file.
func (m *WorkspaceManager) getLockFile() string {
	return filepath.Join(m.getHomeDir(), hiddenLockFile)
}

// isWorkspaceDir checks if the directory is a workspace directory.
func (m *WorkspaceManager) isWorkspaceDir() bool {
	isValid, _ := m.persMgr.CheckFileIfExists(true, "")
	return isValid
}

// tryLock tries to lock the workspace.
func (m *WorkspaceManager) tryLock() (*flock.Flock, error) {
	lockFile := m.getLockFile()
	m.persMgr.CreateFileIfNotExists(true, lockFile)
	fileLock := flock.New(lockFile)
	lock, err := fileLock.TryLock()
	if !lock || err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: could not acquire the lock, another process is using it %s", m.getLockFile()))
	}
	return fileLock, nil
}
