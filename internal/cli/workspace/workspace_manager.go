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

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscfg "github.com/permguard/permguard/internal/cli/workspace/config"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azicliwkslogs "github.com/permguard/permguard/internal/cli/workspace/logs"
	azicliwksrefs "github.com/permguard/permguard/internal/cli/workspace/refs"
	azicliwksobjs "github.com/permguard/permguard/internal/cli/workspace/objects"
	azicliwksplans "github.com/permguard/permguard/internal/cli/workspace/plans"
)

const (
	hiddenDir        	= ".permguard"
)

// WorkspaceManager implements the internal manager to manage the .permguard directory.
type WorkspaceManager struct {
	ctx     *aziclicommon.CliCommandContext
	homeDir string
	persMgr *azicliwkspers.PersistenceManager
	cfgMgr	*azicliwkscfg.ConfigManager
	logsMgr *azicliwkslogs.LogsManager
	rfsMgr  *azicliwksrefs.RefsManager
	objsMgr *azicliwksobjs.ObjectsManager
	plansMgr *azicliwksplans.PlansManager
}

// NewInternalManager creates a new internal manager.
func NewInternalManager(ctx *aziclicommon.CliCommandContext) *WorkspaceManager {
	hdnDir := filepath.Join(ctx.GetWorkDir(), hiddenDir)
	persMgr := azicliwkspers.NewPersistenceManager(hdnDir, ctx)
	return &WorkspaceManager{
		homeDir: hdnDir,
		ctx:     ctx,
		persMgr: persMgr,
		cfgMgr: azicliwkscfg.NewConfigManager(ctx, persMgr),
		logsMgr: azicliwkslogs.NewLogsManager(ctx, persMgr),
		rfsMgr:  azicliwksrefs.NewRefsManager(ctx, persMgr),
		objsMgr: azicliwksobjs.NewObjectsManager(ctx, persMgr),
		plansMgr: azicliwksplans.NewPlansManager(ctx, persMgr),
	}
}

// GetHomeDir returns the home directory.
func (m *WorkspaceManager) GetHomeDir() string {
	return m.homeDir
}

// InitWorkspace the workspace.
func (m *WorkspaceManager) InitWorkspace() (string, error) {
	firstInit := true
	homeDir := m.GetHomeDir()
	err := m.persMgr.CreateDir(false, homeDir)
	if err != nil {
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
			return "", err
		}
	}
	var output string
	if firstInit {
		output = fmt.Sprintf("Initialized empty panicermGuard repository in %s", homeDir)
	} else {
		output = fmt.Sprintf("Reinitialized existing permGuard repository in %s", homeDir)
	}
	return output, nil
}
