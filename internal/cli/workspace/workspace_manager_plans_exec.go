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
	azicliwkscosp "github.com/permguard/permguard/internal/cli/workspace/cosp"
)

// ExecPlan generates a plan of changes to apply to the remote repo based on the differences between the local and remote states.
func (m *WorkspaceManager) ExecPlan(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	return m.execInternalPlan(false, out)
}

// execInternalPlan generates a plan of changes to apply to the remote repo based on the differences between the local and remote states.
func (m *WorkspaceManager) execInternalPlan(internal bool, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	if !m.isWorkspaceDir() {
		return nil, m.raiseWrongWorkspaceDirError(out)
	}
	headInfo, err := m.getCurrentHeadInfo(out)
	if err != nil {
		return nil, err
	}

	output, err := m.execInternalValidate(internal, out)
	if err != nil {
		return output, err
	}

	headRef, err := m.rfsMgr.GetCurrentHeadRef()
	if err != nil {
		return output, err
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "plan", fmt.Sprintf("Head remote set to %s.", aziclicommon.KeywordText(headInfo.Remote)), nil)
		out(nil, "plan", fmt.Sprintf("Head accountid set to %s.", aziclicommon.BigNumberText(headInfo.AccountID)), nil)
		out(nil, "plan", fmt.Sprintf("Head remote_repo set to %s.", aziclicommon.KeywordText(headInfo.Repo)), nil)
		out(nil, "plan", fmt.Sprintf("Head refid set to %s.", aziclicommon.IDText(headInfo.RefID)), nil)
		out(nil, "plan", fmt.Sprintf("Repo set to %s.", aziclicommon.KeywordText(headRef)), nil)
	} else if m.ctx.IsVerboseJSONOutput() {
		remoteObj := map[string]any{
			"remote":      headInfo.Remote,
			"accountid":   headInfo.AccountID,
			"remote_repo": headInfo.Repo,
			"refid":       headInfo.RefID,
		}
		output = out(output, "head", remoteObj, nil)
		output = out(output, "repo", headRef, nil)
	}

	if m.ctx.IsTerminalOutput() {
		out(nil, "", fmt.Sprintf("Initiating the planning process for repo %s.", aziclicommon.KeywordText(headRef)), nil)
	}

	errPlanningProcessFailed := "Planning process failed."
	codeObjState, err := m.cospMgr.ReadCodeState()
	if err != nil {
		if m.ctx.IsTerminalOutput() {
			out(nil, "", errPlanningProcessFailed, nil)
		}
		return output, err
	}
	codeStateObjs, err := m.plan(codeObjState, nil)
	if err != nil {
		if m.ctx.IsTerminalOutput() {
			out(nil, "", errPlanningProcessFailed, nil)
		}
		return output, err
	}

	createdItems := []azicliwkscosp.CodeObject{}
	modifiedItems := []azicliwkscosp.CodeObject{}
	deletedItems := []azicliwkscosp.CodeObject{}
	if len(codeStateObjs) == 0 {
		if m.ctx.IsTerminalOutput() {
			out(nil, "", "No changes detected during the planning phase. system is up to date.", nil)
		}
	} else {
		if m.ctx.IsTerminalOutput() {
			out(nil, "", "Planning process completed successfully.", nil)
			out(nil, "", "The following changes have been identified and are ready to be applied:\n", nil)
		}
		for _, codeStateObj := range codeStateObjs {
			if codeStateObj.State == azicliwkscosp.CodeObjectStateCreate {
				if m.ctx.IsTerminalOutput() {
					out(nil, "", fmt.Sprintf("	%s %s %s", aziclicommon.CreateText("+"), aziclicommon.IDText(codeStateObj.OID), aziclicommon.CreateText(codeStateObj.OName)), nil)
				}
				createdItems = append(createdItems, codeStateObj.CodeObject)
			}
			if codeStateObj.State == azicliwkscosp.CodeObjectStateModify {
				if m.ctx.IsTerminalOutput() {
					out(nil, "", fmt.Sprintf("	%s %s %s", aziclicommon.ModifyText("+"), aziclicommon.IDText(codeStateObj.OID), aziclicommon.ModifyText(codeStateObj.OName)), nil)
				}
				modifiedItems = append(modifiedItems, codeStateObj.CodeObject)
			}
			if codeStateObj.State == azicliwkscosp.CodeObjectStateDelete {
				if m.ctx.IsTerminalOutput() {
					out(nil, "", fmt.Sprintf("	%s %s %s", aziclicommon.DeleteText("+"), aziclicommon.IDText(codeStateObj.OID), aziclicommon.ModifyText(codeStateObj.OName)), nil)
				}
				deletedItems = append(deletedItems, codeStateObj.CodeObject)
			}
		}
		if m.ctx.IsTerminalOutput() {
			out(nil, "", "\n", nil)
			if !internal {
				out(nil, "", "Run the 'apply' command to apply those changes.", nil)
			}
		}
	}
	if m.ctx.IsJSONOutput() {
		changes := map[string]any{}
		changes["create"] = createdItems
		changes["modify"] = modifiedItems
		changes["delete"] = deletedItems
		output["plan"] = changes
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
		return nil, m.raiseWrongWorkspaceDirError(out)
	}
	_, err := m.getCurrentHeadInfo(out)
	if err != nil {
		return nil, err
	}

	_, err = m.execInternalPlan(internal, out)
	if err != nil {
		return nil, err
	}

	// TODO: Implement this method

	return nil, nil
}
