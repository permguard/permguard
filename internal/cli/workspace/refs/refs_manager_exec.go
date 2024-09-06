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

// ExecInitalize the refs resources.
func (m *RefsManager) ExecInitalize() error {
	_, err := m.persMgr.CreateDirIfNotExists(true, m.getRefsDir())
	if err != nil {
		return err
	}
	headFile := m.getHeadFile()
	_, err = m.persMgr.CreateFileIfNotExists(true, headFile)
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
	refPath, err := m.createAndGetHeadRefFile(remote, refID)
	if err != nil {
		return "", "", nil, err
	}
	refCfg := RefsConfig{
		Objects: RefsObjectsConfig{
			Commit: commit,
		},
	}
	err = m.saveConfig(refPath, true, &refCfg)
	if err != nil {
		return "", "", nil, err
	}
	headCfg := HeadConfig{
		Head: HeadRefsConfig{
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
	if m.ctx.IsTerminalOutput() {
		if m.ctx.IsVerbose() {
			output = out(nil, "head", refPath, nil)
		}
	} else {
		remotes := []any{}
		remoteObj := map[string]any{
			"remote":    headCfg.Head.Remote,
			"accountid": headCfg.Head.AccountID,
			"repo":      headCfg.Head.Repo,
			"refid":     headCfg.Head.RefID,
		}
		remotes = append(remotes, remoteObj)
		output = out(output, "head", remotes, nil)
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
