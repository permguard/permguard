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

	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// ExecPlan generates a plan of changes to apply to the remote repo based on the differences between the local and remote states.
func (m *WorkspaceManager) ExecPlan(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	return m.execInternalPlan(false, out)
}

// execInternalPlan generates a plan of changes to apply to the remote repo based on the differences between the local and remote states.
func (m *WorkspaceManager) execInternalPlan(internal bool, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf(ErrMessageCliWorkspaceDirectory, m.getHomeHiddenDir()))
	}

	_, err := m.execInternalValidate(internal, out)
	if err != nil {
		return nil, err
	}

	headInfo, err := m.rfsMgr.GetCurrentHead()
	if err != nil {
		return nil, err
	}

	headRef, err := m.rfsMgr.GetCurrentHeadRef()
	if err != nil {
		return nil, err
	}

	output := map[string]any{}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "plan", fmt.Sprintf("Head remote set to %s.", aziclicommon.KeywordText(headInfo.Remote)), nil)
		out(nil, "plan", fmt.Sprintf("Head accountid set to %s.", aziclicommon.BigNumberText(headInfo.AccountID)), nil)
		out(nil, "plan", fmt.Sprintf("Head remote_repo set to %s.", aziclicommon.KeywordText(headInfo.Repo)), nil)
		out(nil, "plan", fmt.Sprintf("Head refid set to %s.", aziclicommon.IDText(headInfo.RefID)), nil)
		out(nil, "plan", fmt.Sprintf("Repo set to %s.", aziclicommon.KeywordText(headRef)), nil)
	} else if m.ctx.IsVerboseJSONOutput() {
		remoteObj := map[string]any{
			"remote":    headInfo.Remote,
			"accountid": headInfo.AccountID,
			"remote_repo": headInfo.Repo,
			"refid":     headInfo.RefID,
		}
		output = out(output, "head", remoteObj, nil)
		output = out(output, "repo", headRef, nil)
	}

	if m.ctx.IsTerminalOutput() {
		out(nil, "", fmt.Sprintf("Initiating the planning process for repo %s.", aziclicommon.KeywordText(headRef)), nil)
	}

	err = m.plan()
	if err != nil {
		if m.ctx.IsTerminalOutput() {
			out(nil, "", "Planning process failed.", nil)
		}
		return nil, err
	}
	if m.ctx.IsTerminalOutput() {
		out(nil, "", "Planning process completed successfully.", nil)
	}
	return output, nil
}

// ExecApply applies the plan to the remote repo
func (m *WorkspaceManager) ExecApply(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	return m.execInternalApply(false, out)
}

// execInternalApply applies the plan to the remote repo
func (m *WorkspaceManager) execInternalApply(internal bool, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliWorkspaceDir, fmt.Sprintf(ErrMessageCliWorkspaceDirectory, m.getHomeHiddenDir()))
	}

	_, err := m.execInternalPlan(internal, out)
	if err != nil {
		return nil, err
	}

	// TODO: Implement this method

	return nil, nil
}
