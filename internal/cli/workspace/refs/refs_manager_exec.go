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

package ref

import (
	"fmt"

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
)

// ExecInitalize the ref resources.
func (m *RefManager) ExecInitalize() error {
	_, err := m.persMgr.CreateDirIfNotExists(azicliwkspers.PermguardDir, m.getRefsDir())
	if err != nil {
		return err
	}
	headFile := m.getHeadFile()
	_, err = m.persMgr.CreateFileIfNotExists(azicliwkspers.PermguardDir, headFile)
	if err != nil {
		return err
	}
	return nil
}

// ExecCheckoutRefFilesForRemote checks out the remote refs files for the remote.
func (m *RefManager) ExecCheckoutRefFilesForRemote(remote string, zoneID int64, ledger string, ledgerID string, commit string, output map[string]any, out aziclicommon.PrinterOutFunc) (string, string, map[string]any, error) {
	if output == nil {
		output = map[string]any{}
	}
	remoteRef := azicliwkscommon.GenerateRemoteRef(remote, zoneID, ledgerID)
	err := m.SaveRefConfig(ledgerID, remoteRef, commit)
	if err != nil {
		return "", "", output, err
	}
	headRef := azicliwkscommon.GenerateHeadRef(zoneID, ledgerID)
	err = m.SaveRefWithRemoteConfig(ledgerID, headRef, remoteRef, commit)
	if err != nil {
		return "", "", output, err
	}
	return remoteRef, headRef, output, nil
}

// ExecCheckoutHead checks out the head.
func (m *RefManager) ExecCheckoutHead(ref string, output map[string]any, out aziclicommon.PrinterOutFunc) (*azicliwkscommon.HeadInfo, map[string]any, error) {
	if output == nil {
		output = map[string]any{}
	}
	err := m.SaveHeadConfig(ref)
	if err != nil {
		return nil, output, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "head", fmt.Sprintf("Head successfully set to %s.", aziclicommon.KeywordText(ref)), nil, true)
	} else if m.ctx.IsVerboseJSONOutput() {
		remoteObj := map[string]any{
			"ref": ref,
		}
		output = out(output, "head", remoteObj, nil, true)
	}
	headInfo, err := m.GetCurrentHead()
	if err != nil {
		return nil, output, err
	}
	return headInfo, output, nil
}
