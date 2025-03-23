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
	"os"
	"path/filepath"

	"github.com/gofrs/flock"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscfg "github.com/permguard/permguard/internal/cli/workspace/config"
	azicliwkscosp "github.com/permguard/permguard/internal/cli/workspace/cosp"
	azicliwkslogs "github.com/permguard/permguard/internal/cli/workspace/logs"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azicliwksrefs "github.com/permguard/permguard/internal/cli/workspace/refs"
	azicliwksremotesrv "github.com/permguard/permguard/internal/cli/workspace/remoteserver"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlang "github.com/permguard/permguard/pkg/languages"
)

const (
	// hiddenDir represents the permguard's hidden directory.
	hiddenDir = ".permguard"
	// hiddenDir represents the permguard's hidden ignore file.
	hiddenIgnoreFile = ".permguardignore"
	// hiddenLockFile represents the permguard's lock file.
	hiddenLockFile = "permguard.lock"
	// gitDir represents the git directory.
	gitDir = ".git"
	// gitIgnoreFile represents the git ignore file.
	gitIgnoreFile = ".gitignore"
)

// WorkspaceManager implements the internal manager to manage the .permguard directory.
type WorkspaceManager struct {
	ctx       *aziclicommon.CliCommandContext
	homeDir   string
	objMar    *azlangobjs.ObjectManager
	langFct   azlang.LanguageFactory
	persMgr   *azicliwkspers.PersistenceManager
	rmSrvtMgr *azicliwksremotesrv.RemoteServerManager
	cfgMgr    *azicliwkscfg.ConfigManager
	logsMgr   *azicliwkslogs.LogsManager
	rfsMgr    *azicliwksrefs.RefManager
	cospMgr   *azicliwkscosp.COSPManager
}

// NewInternalManager creates a new internal manager.
func NewInternalManager(ctx *aziclicommon.CliCommandContext, langFct azlang.LanguageFactory) (*WorkspaceManager, error) {
	homeDir := ctx.GetWorkDir()
	objMar, err := azlangobjs.NewObjectManager()
	if err != nil {
		return nil, err
	}
	persMgr, err := azicliwkspers.NewPersistenceManager(homeDir, hiddenDir, ctx)
	if err != nil {
		return nil, err
	}
	rmSrvtMgr, err := azicliwksremotesrv.NewRemoteServerManager(ctx)
	if err != nil {
		return nil, err
	}
	cfgMgr, err := azicliwkscfg.NewConfigManager(ctx, persMgr)
	if err != nil {
		return nil, err
	}
	logsMgr, err := azicliwkslogs.NewLogsManager(ctx, persMgr)
	if err != nil {
		return nil, err
	}
	rfsMgr, err := azicliwksrefs.NewRefManager(ctx, persMgr)
	if err != nil {
		return nil, err
	}
	cospMgr, err := azicliwkscosp.NewPlansManager(ctx, persMgr)
	if err != nil {
		return nil, err
	}
	return &WorkspaceManager{
		homeDir:   homeDir,
		ctx:       ctx,
		objMar:    objMar,
		langFct:   langFct,
		persMgr:   persMgr,
		rmSrvtMgr: rmSrvtMgr,
		cfgMgr:    cfgMgr,
		logsMgr:   logsMgr,
		rfsMgr:    rfsMgr,
		cospMgr:   cospMgr,
	}, nil
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
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	currentDir := m.persMgr.GetPath(azicliwkspers.WorkspaceDir, "")
	currentDir, err = filepath.Abs(currentDir)
	if err != nil {
		return false
	}
	if homeDir == currentDir {
		return false
	}
	isValid, _ := m.persMgr.CheckPathIfExists(azicliwkspers.PermguardDir, "")
	return isValid
}

// tryLock tries to lock the workspace.
func (m *WorkspaceManager) tryLock() (*flock.Flock, error) {
	lockFile := m.getLockFile()
	m.persMgr.CreateFileIfNotExists(azicliwkspers.WorkDir, lockFile)
	fileLock := flock.New(lockFile)
	lock, err := fileLock.TryLock()
	if !lock || err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliFileOperation, fmt.Sprintf("could not acquire the lock, another process is using it %s", m.getLockFile()), err)
	}
	return fileLock, nil
}

// raiseWrongWorkspaceDirError raises an error when the directory is not a workspace directory.
func (m *WorkspaceManager) raiseWrongWorkspaceDirError(out aziclicommon.PrinterOutFunc) error {
	out(nil, "", "The current working directory is not a valid Permguard workspace.", nil, true)
	out(nil, "", "Please initialize the workspace by running the 'init' command.", nil, true)
	return azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliWorkspaceDir, fmt.Sprintf("%s is not a permguard workspace directory", m.getHomeHiddenDir()))
}
