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
	azvalidators "github.com/permguard/permguard/pkg/extensions/validators"
	azicliwksremote "github.com/permguard/permguard/internal/cli/workspace/remote"
	azicliwkscfg "github.com/permguard/permguard/internal/cli/workspace/config"
	azicliwkslogs "github.com/permguard/permguard/internal/cli/workspace/logs"
	azicliwksobjs "github.com/permguard/permguard/internal/cli/workspace/objects"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azicliwksplans "github.com/permguard/permguard/internal/cli/workspace/plans"
	azicliwksrefs "github.com/permguard/permguard/internal/cli/workspace/refs"
	azicliwksvals "github.com/permguard/permguard/internal/cli/workspace/validators"
	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
)

const (
	hiddenDir      = ".permguard"
	hiddenLockFile = "permguard.lock"
)

// WorkspaceManager implements the internal manager to manage the .permguard directory.
type WorkspaceManager struct {
	ctx      	*aziclicommon.CliCommandContext
	homeDir  	string
	persMgr  	*azicliwkspers.PersistenceManager
	remoteMgr 	*azicliwksremote.RemoteManager
	cfgMgr   	*azicliwkscfg.ConfigManager
	logsMgr  	*azicliwkslogs.LogsManager
	rfsMgr   	*azicliwksrefs.RefsManager
	objsMgr  	*azicliwksobjs.ObjectsManager
	plansMgr 	*azicliwksplans.PlansManager
}

// NewInternalManager creates a new internal manager.
func NewInternalManager(ctx *aziclicommon.CliCommandContext) *WorkspaceManager {
	hdnDir := filepath.Join(ctx.GetWorkDir(), hiddenDir)
	persMgr := azicliwkspers.NewPersistenceManager(hdnDir, ctx)
	return &WorkspaceManager{
		homeDir:   hdnDir,
		ctx:       ctx,
		persMgr:   persMgr,
		remoteMgr: azicliwksremote.NewRemoteManager(ctx),
		cfgMgr:    azicliwkscfg.NewConfigManager(ctx, persMgr),
		logsMgr:  azicliwkslogs.NewLogsManager(ctx, persMgr),
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

// IsValidHomeDir checks if the home directory is valid.
func (m *WorkspaceManager) isValidHomeDir() bool {
	isValid, _ := m.persMgr.CheckFileIfExists(true, "")
	return isValid
}

// InitWorkspace the workspace.
func (m *WorkspaceManager) InitWorkspace(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	firstInit := true
	homeDir := m.getHomeDir()
	res, err := m.persMgr.CreateDirIfNotExists(false, homeDir)
	if err != nil {
		return nil, err
	}

	lockFile := m.getLockFile()
	m.persMgr.CreateFileIfNotExists(true, lockFile)
	fileLock := flock.New(lockFile)
	lock, err := fileLock.TryLock()
	if !lock || err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: could not acquire the lock, another process is using it %s", m.getLockFile()))
	}
	defer fileLock.Unlock()

	if !res {
		firstInit = false
	}
	initializers := []func() error{
		m.cfgMgr.Initialize,
		m.logsMgr.Initalize,
		m.rfsMgr.Initalize,
		m.objsMgr.Initalize,
		m.plansMgr.Initalize,
	}
	for _, initializer := range initializers {
		err := initializer()
		if err != nil {
			return nil, err
		}
	}
	var msg string
	var output map[string]any
	if m.ctx.IsTerminalOutput() {
		if firstInit {
			msg = fmt.Sprintf("Initialized empty PermGuard repository in %s", homeDir)
		} else {
			msg = fmt.Sprintf("Reinitialized existing PermGuard repository in %s", homeDir)
		}
		output = out(nil, "init", msg, nil)
	} else {
		remotes := []interface{}{}
		remoteObj := map[string]any{
			"cwd": m.getHomeDir(),
		}
		remotes = append(remotes, remoteObj)
		output = out(nil, "workspaces", remotes, nil)
	}
	return output, nil
}

// AddRemote adds a remote.
func (m *WorkspaceManager) AddRemote(remote string, server string, aap int, pap int, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isValidHomeDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf("cli: %s is not a permguard workspace directory", m.getHomeDir()))
	}
	if !azvalidators.IsValidHostname(server) {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid server %s", server))
	}
	if !azvalidators.IsValidPort(aap) {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid aap port %d", aap))
	}
	if !azvalidators.IsValidPort(pap) {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid pap port %d", pap))
	}

	fileLock := flock.New(m.getLockFile())
	lock, err := fileLock.TryLock()
	if !lock || err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: could not acquire the lock, another process is using it %s", m.getLockFile()))
	}
	defer fileLock.Unlock()

	output := map[string]any{}
	return m.cfgMgr.AddRemote(remote, server, aap, pap, output, out)
}

// RemoveRemote removes a remote.
func (m *WorkspaceManager) RemoveRemote(remote string, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isValidHomeDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf("cli: %s is not a permguard workspace directory", m.getHomeDir()))
	}

	fileLock := flock.New(m.getLockFile())
	lock, err := fileLock.TryLock()
	if !lock || err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: could not acquire the lock, another process is using it %s", m.getLockFile()))
	}
	defer fileLock.Unlock()

	headRemote, _, _, _, err := m.rfsMgr.GetCurrentHead()
	if err != nil {
		return nil, err
	}
	if headRemote == remote {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspace, fmt.Sprintf("cli: cannot remove the remote used by the currently checked out account %s", remote))
	}

	output := map[string]any{}
	return m.cfgMgr.RemoveRemote(remote, output, out)
}

// ListRemotes lists the remotes.
func (m *WorkspaceManager) ListRemotes(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isValidHomeDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf("cli: %s is not a permguard workspace directory", m.getHomeDir()))
	}

	fileLock := flock.New(m.getLockFile())
	lock, err := fileLock.TryLock()
	if !lock || err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: could not acquire the lock, another process is using it %s", m.getLockFile()))
	}
	defer fileLock.Unlock()

	output := map[string]any{}
	return m.cfgMgr.ListRemotes(output, out)
}

// CheckoutRepo checks out a repository.
func (m *WorkspaceManager) CheckoutRepo(repo string, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isValidHomeDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf("cli: %s is not a permguard workspace directory", m.getHomeDir()))
	}

	remoteName, accountID, repoName, err := azicliwksvals.SanitizeRepo(repo)
	if err != nil {
		return nil, err
	}

	fileLock := flock.New(m.getLockFile())
	lock, err := fileLock.TryLock()
	if !lock || err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: could not acquire the lock, another process is using it %s", m.getLockFile()))
	}
	defer fileLock.Unlock()
	cfgRemote, err := m.cfgMgr.GetRemote(remoteName)
	if err != nil {
		return nil, err
	}
	srvRepo, err := m.remoteMgr.GetServerRemoteRepo(accountID, repoName, cfgRemote.Server, cfgRemote.AAP, cfgRemote.PAP)
	if err != nil {
		return nil, err
	}
	output := map[string]any{}
	output, err = m.rfsMgr.CheckoutHead(remoteName, accountID, repoName, srvRepo.Refs, output, out)
	if err != nil {
		return nil, err
	}
	output, err = m.cfgMgr.AddRepo(remoteName, accountID, repoName, output, out)
	if err != nil && !azerrors.AreErrorsEqual(err, azerrors.ErrCliRecordExists) {
		return nil, err
	}
	return output, nil
}

// ListRepos lists the repos.
func (m *WorkspaceManager) ListRepos(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isValidHomeDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf("cli: %s is not a permguard workspace directory", m.getHomeDir()))
	}

	fileLock := flock.New(m.getLockFile())
	lock, err := fileLock.TryLock()
	if !lock || err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, fmt.Sprintf("cli: could not acquire the lock, another process is using it %s", m.getLockFile()))
	}
	defer fileLock.Unlock()

	remote, accountID, repo, _, errr := m.rfsMgr.GetCurrentHead()
	if errr != nil {
		return nil, errr
	}
	refRepo := fmt.Sprintf("%s/%d/%s", remote, accountID, repo)

	output := map[string]any{}
	return m.cfgMgr.ListRepos(refRepo, output, out)
}
