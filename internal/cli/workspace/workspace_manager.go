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
	"path/filepath"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscfg "github.com/permguard/permguard/internal/cli/workspace/config"
	azicliwkslogs "github.com/permguard/permguard/internal/cli/workspace/logs"
	azicliwksobjs "github.com/permguard/permguard/internal/cli/workspace/objects"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azicliwksplans "github.com/permguard/permguard/internal/cli/workspace/plans"
	azicliwksrefs "github.com/permguard/permguard/internal/cli/workspace/refs"
	azicliwksremote "github.com/permguard/permguard/internal/cli/workspace/remote"
)

const (
	// hiddenDir represents the permguard's hidden directory.
	hiddenDir = ".permguard"
)

// WorkspaceManager implements the internal manager to manage the .permguard directory.
type WorkspaceManager struct {
	ctx      *aziclicommon.CliCommandContext
	homeDir  string
	persMgr  *azicliwkspers.PersistenceManager
	rmtMgr   *azicliwksremote.RemoteManager
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
		rmtMgr:   azicliwksremote.NewRemoteManager(ctx),
		cfgMgr:   azicliwkscfg.NewConfigManager(ctx, persMgr),
		logsMgr:  azicliwkslogs.NewLogsManager(ctx, persMgr),
		rfsMgr:   azicliwksrefs.NewRefsManager(ctx, persMgr),
		objsMgr:  azicliwksobjs.NewObjectsManager(ctx, persMgr),
		plansMgr: azicliwksplans.NewPlansManager(ctx, persMgr),
	}
}
