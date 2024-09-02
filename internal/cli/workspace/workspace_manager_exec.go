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
)

// ExecInitWorkspace the workspace.
func (m *WorkspaceManager) ExecInitWorkspace(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	homeDir := m.getHomeDir()
	res, err := m.persMgr.CreateDirIfNotExists(false, homeDir)
	if err != nil {
		return nil, err
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return nil, err
	}
	defer fileLock.Unlock()

	firstInit := true
	if !res {
		firstInit = false
	}
	initializers := []func() error{
		m.logsMgr.ExecInitalize,
		m.cfgMgr.ExecInitialize,
		m.rfsMgr.ExecInitalize,
		m.objsMgr.ExecInitalize,
		m.plansMgr.ExecInitalize,
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
