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
	azicliwksrefs "github.com/permguard/permguard/internal/cli/workspace/refs"
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

	headRef, err := m.rfsMgr.GetCurrentHeadRef()
	if err != nil {
		return nil, err
	}

	output, err := m.execInternalValidate(true, out)
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

	out(nil, "", fmt.Sprintf("Initiating the planning process for repo %s.", aziclicommon.KeywordText(headRef)), nil)

	errPlanningProcessFailed := "Planning process failed."

	commit, err := m.rfsMgr.ReadRefsCommit(headInfo.Remote, headInfo.RefID)
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("Unable to read the commit for remote %s and refid %s.",  aziclicommon.KeywordText(headInfo.Remote), aziclicommon.IDText(headInfo.RefID)), nil)
		}
		out(nil, "", errPlanningProcessFailed, nil)
		return nil, err
	}

	var remoteFiles []azicliwkscosp.CodeObjectState = nil
	if commit == azicliwksrefs.ZeroOID {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("The reference ID %s has no commits associated with it.", aziclicommon.IDText(headInfo.RefID)), nil)
		}
	}

	codeObjState, err := m.cospMgr.ReadCodeState()
	if err != nil {
		out(nil, "", errPlanningProcessFailed, nil)
		return output, err
	}
	codeStateObjs, err := m.plan(codeObjState, remoteFiles)
	if err != nil {
		out(nil, "", errPlanningProcessFailed, nil)
		return output, err
	}

	unchangedItems := []azicliwkscosp.CodeObjectState{}
	createdItems := []azicliwkscosp.CodeObjectState{}
	modifiedItems := []azicliwkscosp.CodeObjectState{}
	deletedItems := []azicliwkscosp.CodeObjectState{}
	if len(codeStateObjs) == 0 {
		out(nil, "", "No changes detected during the planning phase. system is up to date.", nil)
	} else {
		out(nil, "", "Planning process completed successfully.", nil)
		out(nil, "", "The following changes have been identified and are ready to be applied:\n", nil)
		for _, codeStateObj := range codeStateObjs {
			if codeStateObj.State == azicliwkscosp.CodeObjectStateUnchanged {
				out(nil, "", fmt.Sprintf("	%s %s %s", aziclicommon.UnchangedText("="), aziclicommon.IDText(codeStateObj.OID), aziclicommon.UnchangedText(codeStateObj.OName)), nil)
				unchangedItems = append(unchangedItems, codeStateObj)
			}
			if codeStateObj.State == azicliwkscosp.CodeObjectStateCreate {
				out(nil, "", fmt.Sprintf("	%s %s %s", aziclicommon.CreateText("+"), aziclicommon.IDText(codeStateObj.OID), aziclicommon.CreateText(codeStateObj.OName)), nil)
				createdItems = append(createdItems, codeStateObj)
			}
			if codeStateObj.State == azicliwkscosp.CodeObjectStateModify {
				out(nil, "", fmt.Sprintf("	%s %s %s", aziclicommon.ModifyText("~"), aziclicommon.IDText(codeStateObj.OID), aziclicommon.ModifyText(codeStateObj.OName)), nil)
				modifiedItems = append(modifiedItems, codeStateObj)
			}
			if codeStateObj.State == azicliwkscosp.CodeObjectStateDelete {
				out(nil, "", fmt.Sprintf("	%s %s %s", aziclicommon.DeleteText("-"), aziclicommon.IDText(codeStateObj.OID), aziclicommon.DeleteText(codeStateObj.OName)), nil)
				deletedItems = append(deletedItems, codeStateObj)
			}
		}
		out(nil, "", "", nil)
		planObjs := append(createdItems, modifiedItems...)
		planObjs = append(planObjs, unchangedItems...)
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("Remote for the plan is set to: %s.", aziclicommon.KeywordText(headInfo.Remote)), nil)
			out(nil, "plan", fmt.Sprintf("Reference ID for the plan is set to: %s", aziclicommon.IDText(headInfo.RefID)), nil)
			out(nil, "plan", "Preparing to save the plan.", nil)
		}
		err := m.cospMgr.SaveCodePlan(headInfo.Remote, headInfo.RefID, planObjs)
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "plan", "Failed to save the plan.", nil)
			}
			out(nil, "", "Unable to save the plan.", nil)
			return output, err
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", "Plan saved successfully.", nil)
		}
		if !internal {
			out(nil, "", "Run the 'apply' command to apply the changes.", nil)
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
	headInfo, err := m.getCurrentHeadInfo(out)
	if err != nil {
		return nil, err
	}
	headRef, err := m.rfsMgr.GetCurrentHeadRef()
	if err != nil {
		return nil, err
	}
	lang, err := m.cfgMgr.GetLanguage()
	if err != nil {
		return nil, err
	}
	absLang, err := m.langFct.CreateLanguageAbastraction(lang)
	if err != nil {
		return nil, err
	}

	output, err := m.execInternalPlan(true, out)
	if err != nil {
		return nil, err
	}

	out(nil, "", fmt.Sprintf("Initiating the apply process for repo %s.", aziclicommon.KeywordText(headRef)), nil)

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", "Preparing to read the plan.", nil)
	}
	errPlanningProcessFailed := "Apply process failed."
	plan, err := m.cospMgr.ReadCodePlan(headInfo.Remote, headInfo.RefID)
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "apply", "Failed to read the plan.", nil)
		}
		out(nil, "", errPlanningProcessFailed, nil)
		return output, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", "The plan has been read successfully.", nil)
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", "Preparing to build the tree.", nil)
	}
	_, treeObj, err := m.buildPlanTree(plan, absLang)
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "apply", "Failed to build the tree.", nil)
		}
		out(nil, "", errPlanningProcessFailed, nil)
		return output, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", fmt.Sprintf("The tree has been created with id: %s.", aziclicommon.IDText(treeObj.GetOID())), nil)
	}

	out(nil, "", "", nil)
	for _, planObj := range plan {
		if planObj.State == azicliwkscosp.CodeObjectStateUnchanged {
			continue
		}
		out(nil, "", fmt.Sprintf("%s object with id: %s, type %s and name: %s.", aziclicommon.RemoteOperationText("Synchornizing"),
			aziclicommon.IDText(planObj.OID), aziclicommon.KeywordText(planObj.OType), aziclicommon.KeywordText(planObj.OName)), nil)
	}
	out(nil, "", "", nil)

	out(nil, "", "Apply process completed successfully.", nil)
	if !internal {
		out(nil, "", fmt.Sprintf("Your workspace is synchronized with the remote repo: %s.", aziclicommon.KeywordText(headRef)), nil)
	}
	return output, nil
}
