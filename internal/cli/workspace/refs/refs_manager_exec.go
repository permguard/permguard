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

package refs

import (
	"fmt"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
)

// ExecInitalize the refs resources.
func (m *RefsManager) ExecInitalize(lang string) error {
	_, err := m.persMgr.CreateDirIfNotExists(azicliwkspers.PermGuardDir, m.getRefsDir())
	if err != nil {
		return err
	}
	headFile := m.getHeadFile()
	_, err = m.persMgr.CreateFileIfNotExists(azicliwkspers.PermGuardDir, headFile)
	if err != nil {
		return err
	}
	return nil
}

// ExecCheckoutHead checks out the head.
func (m *RefsManager) ExecCheckoutHead(remote string, accountID int64, repo string, commit string, output map[string]any, out aziclicommon.PrinterOutFunc) (*HeadInfo, map[string]any, error) {
	if output == nil {
		output = map[string]any{}
	}
	refs := generateRefs(remote, accountID, repo)
	err := m.SaveRefsConfig(refs, commit)
	if err != nil {
		return nil, output, err
	}
	err = m.SaveHeadConfig(refs)
	if err != nil {
		return nil, output, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "head", fmt.Sprintf("Head successfully set to %s.", aziclicommon.KeywordText(refs)), nil, true)
	} else if m.ctx.IsVerboseJSONOutput() {
		remoteObj := map[string]any{
			"refs": refs,
		}
		output = out(output, "head", remoteObj, nil, true)
	}
	headInfo, err := m.GetCurrentHead()
	if err != nil {
		return nil, output, err
	}
	return headInfo, output, nil
}
