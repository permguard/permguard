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

// CheckoutHead checks out the head.
func (m *RefsManager) CheckoutHead(remote string, accountID int64, repo string, commit string, output map[string]any, out func(map[string]any, string, any, error) map[string]any) (string, string, map[string]any, error) {
	if output == nil {
		output = map[string]any{}
	}
	refID, err := m.CalculateRefID(remote, accountID, repo)
	if err != nil {
		return "", "", nil, err
	}

	refPath, err := m.SaveRefsConfig(remote, refID, commit)
	if err != nil {
		return "", "", nil, err
	}

	headCfg := headConfig{
		Head: headRefsConfig{
			Remote:    remote,
			AccountID: accountID,
			Repo:      repo,
			RefID:     refID,
		},
	}
	headFile := m.getHeadFile()
	err = m.saveConfig(headFile, true, &headCfg)
	if err != nil {
		return "", "", nil, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "head", fmt.Sprintf("Head remote successfully set to %s.", aziclicommon.KeywordText(headCfg.Head.Remote)), nil)
		out(nil, "head", fmt.Sprintf("Head accountid successfully set to %s.", aziclicommon.BigNumberText(headCfg.Head.AccountID)), nil)
		out(nil, "head", fmt.Sprintf("Head remote_repo successfully set to %s.", aziclicommon.KeywordText(headCfg.Head.Repo)), nil)
		out(nil, "head", fmt.Sprintf("Head refid successfully set to %s.", aziclicommon.IDText(headCfg.Head.RefID)), nil)
		out(nil, "head", fmt.Sprintf("Head reference checked out to %s.", aziclicommon.KeywordText(refPath)), nil)
	} else if m.ctx.IsVerboseJSONOutput() {
		remoteObj := map[string]any{
			"remote":      headCfg.Head.Remote,
			"accountid":   headCfg.Head.AccountID,
			"remote_repo": headCfg.Head.Repo,
			"refid":       headCfg.Head.RefID,
		}
		output = out(output, "head", remoteObj, nil)
	}
	ref, err := m.GetCurrentHeadRef()
	if err != nil {
		return "", "", nil, err
	}
	refID, err = m.CalculateCurrentHeadRefID()
	if err != nil {
		return "", "", nil, err
	}
	return ref, refID, output, nil
}
