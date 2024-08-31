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

	azerrors "github.com/permguard/permguard/pkg/extensions/errors"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscfg "github.com/permguard/permguard/internal/cli/workspace/config"
	azicliwkslogs "github.com/permguard/permguard/internal/cli/workspace/logs"
	azicliwksobjs "github.com/permguard/permguard/internal/cli/workspace/objects"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azicliwksplans "github.com/permguard/permguard/internal/cli/workspace/plans"
	azicliwksrefs "github.com/permguard/permguard/internal/cli/workspace/refs"
)

const (
	hiddenDir = ".permguard"
)

// WorkspaceManager implements the internal manager to manage the .permguard directory.
type WorkspaceManager struct {
	ctx      *aziclicommon.CliCommandContext
	homeDir  string
	persMgr  *azicliwkspers.PersistenceManager
	cfgMgr   *azicliwkscfg.ConfigManager
	logsMgr  *azicliwkslogs.LogsManager
	rfsMgr   *azicliwksrefs.RefsManager
	objsMgr  *azicliwksobjs.ObjectsManager
	plansMgr *azicliwksplans.PlansManager
}

// NewInternalManager creates a new internal manager.
func NewInternalManager(ctx *aziclicommon.CliCommandContext) *WorkspaceManager {
	hdnDir := filepath.Join(ctx.GetWorkDir(), hiddenDir)
	persMgr := azicliwkspers.NewPersistenceManager(hdnDir, ctx)
	return &WorkspaceManager{
		homeDir:  hdnDir,
		ctx:      ctx,
		persMgr:  persMgr,
		cfgMgr:   azicliwkscfg.NewConfigManager(ctx, persMgr),
		logsMgr:  azicliwkslogs.NewLogsManager(ctx, persMgr),
		rfsMgr:   azicliwksrefs.NewRefsManager(ctx, persMgr),
		objsMgr:  azicliwksobjs.NewObjectsManager(ctx, persMgr),
		plansMgr: azicliwksplans.NewPlansManager(ctx, persMgr),
	}
}

// GetHomeDir returns the home directory.
func (m *WorkspaceManager) GetHomeDir() string {
	return m.homeDir
}

// IsValidHomeDir checks if the home directory is valid.
func (m *WorkspaceManager) isValidHomeDir() bool {
	isValid, _ := m.persMgr.CheckFileIfExists(true, "")
	return isValid
}

// InitWorkspace the workspace.
func (m *WorkspaceManager) InitWorkspace(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	firstInit := true
	homeDir := m.GetHomeDir()
	res, err := m.persMgr.CreateDirIfNotExists(false, homeDir)
	if err != nil {
		return nil, err
	}
	if !res {
		firstInit = false
	}
	initializers := []func() error{
		m.cfgMgr.Initialize,
		m.logsMgr.Iniitalize,
		m.rfsMgr.Iniitalize,
		m.objsMgr.Iniitalize,
		m.plansMgr.Iniitalize,
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
			"cwd": m.GetHomeDir(),
		}
		remotes = append(remotes, remoteObj)
		output = out(nil, "workspaces", remotes, nil)
	}
	return output, nil
}

// AddRemote adds a remote.
func (m *WorkspaceManager) AddRemote(remote string, server string, aap int, pap int, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isValidHomeDir(){
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf("cli: %s is not a permguard workspace directory", m.GetHomeDir()))
	}
	return m.cfgMgr.AddRemote(remote, server, aap, pap, out)
}

// RemoveRemote removes a remote.
func (m *WorkspaceManager) RemoveRemote(remote string, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isValidHomeDir(){
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf("cli: %s is not a permguard workspace directory", m.GetHomeDir()))
	}
	return m.cfgMgr.RemoveRemote(remote, out)
}

// ListRemotes lists the remotes.
func (m *WorkspaceManager) ListRemotes(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isValidHomeDir(){
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf("cli: %s is not a permguard workspace directory", m.GetHomeDir()))
	}
	return m.cfgMgr.ListRemotes(out)
}
