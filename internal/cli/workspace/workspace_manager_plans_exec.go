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
	azicliwkscosp "github.com/permguard/permguard/internal/cli/workspace/cosp"
	azicliwksrefs "github.com/permguard/permguard/internal/cli/workspace/refs"
)

// ExecPlan generates a plan of changes to apply to the remote repo based on the differences between the local and remote states.
func (m *WorkspaceManager) ExecPlan(out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	return m.execInternalPlan(false, out)
}

// execInternalPlan generates a plan of changes to apply to the remote repo based on the differences between the local and remote states.
func (m *WorkspaceManager) execInternalPlan(internal bool, out func(map[string]any, string, any, error) map[string]any) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to build the plan.", nil)
		return output, err
	}

	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	headRef, err := m.rfsMgr.GetCurrentHeadRefs()
	if err != nil || headRef == "" {
		out(nil, "", "Please ensure a valid remote repo is checked out.", nil)
		if err == nil {
			 err = azerrors.WrapSystemError(azerrors.ErrCliWorkspace, "cli: invalid head refs")
		}
		return failedOpErr(nil, err)
	}

	refsInfo, err := m.rfsMgr.GetCurrentHeadRefsInfo()
	if err != nil {
		return failedOpErr(nil, err)
	}

	output, err := m.execInternalValidate(true, out)
	if err != nil {
		return failedOpErr(output, err)
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "plan", fmt.Sprintf("Head successfully set to %s.", aziclicommon.KeywordText(headRef)), nil)
		out(nil, "plan", fmt.Sprintf("Repo set to %s.", aziclicommon.KeywordText(refsInfo.GetRepoURI())), nil)
	} else if m.ctx.IsVerboseJSONOutput() {
		remoteObj := map[string]any{
			"refs": headRef,
		}
		output = out(output, "head", remoteObj, nil)
		output = out(output, "repo", refsInfo.GetRepoURI(), nil)
	}

	out(nil, "", fmt.Sprintf("Initiating the planning process for repo %s.", aziclicommon.KeywordText(refsInfo.GetRepoURI())), nil)

	errPlanningProcessFailed := "Planning process failed."

	commit, err := m.rfsMgr.GetRefsCommit(headRef)
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("Unable to read the commit for refs %s.", aziclicommon.KeywordText(headRef)), nil)
		}
		out(nil, "", errPlanningProcessFailed, nil)
		return failedOpErr(nil, err)
	}

	var remoteCodeState []azicliwkscosp.CodeObjectState = nil
	if commit == azicliwksrefs.ZeroOID {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("The refs %s has no commits associated with it.", aziclicommon.KeywordText(headRef)), nil)
		}
	}

	localCodeState, err := m.cospMgr.ReadCodeSourceCodeState()
	if err != nil {
		out(nil, "", errPlanningProcessFailed, nil)
		return failedOpErr(output, err)
	}
	codeStateObjs, err := m.plan(localCodeState, remoteCodeState)
	if err != nil {
		out(nil, "", errPlanningProcessFailed, nil)
		return failedOpErr(output, err)
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
		refsInfo, err := m.rfsMgr.GetCurrentHeadRefsInfo()
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "plan", "Failed to retrieve the current head refs info.", nil)
			}
			out(nil, "", "Unable to build the plan.", nil)
			return failedOpErr(output, err)
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("Remote for the plan is set to: %s.", aziclicommon.KeywordText(refsInfo.GetRemote())), nil)
			out(nil, "plan", fmt.Sprintf("Reference ID for the plan is set to: %s", aziclicommon.IDText(refsInfo.GetRefID())), nil)
			out(nil, "plan", "Preparing to save the plan.", nil)
		}
		err = m.cospMgr.SaveRemoteCodePlan(refsInfo.GetRemote(), refsInfo.GetRefID(), planObjs)
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "plan", "Failed to save the plan.", nil)
			}
			out(nil, "", "Unable to save the plan.", nil)
			return failedOpErr(output, err)
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
		changes["unchanged"] = unchangedItems
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
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to apply the plan.", nil)
		return output, err
	}

	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	refsInfo, err := m.rfsMgr.GetCurrentHeadRefsInfo()
	if err != nil {
		return failedOpErr(nil, err)
	}

	lang, err := m.cfgMgr.GetLanguage()
	if err != nil {
		return failedOpErr(nil, err)
	}
	absLang, err := m.langFct.CreateLanguageAbastraction(lang)
	if err != nil {
		return failedOpErr(nil, err)
	}

	output, err := m.execInternalPlan(true, out)
	if err != nil {
		return failedOpErr(nil, err)
	}

	out(nil, "", fmt.Sprintf("Initiating the apply process for repo %s.", aziclicommon.KeywordText(refsInfo.GetRepoURI())), nil)

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", "Preparing to read the plan.", nil)
	}
	errPlanningProcessFailed := "Apply process failed."
	plan, err := m.cospMgr.ReadRemoteCodePlan(refsInfo.GetRemote(), refsInfo.GetRefID())
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "apply", "Failed to read the plan.", nil)
		}
		out(nil, "", errPlanningProcessFailed, nil)
		return failedOpErr(output, err)
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
		return failedOpErr(output, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", fmt.Sprintf("The tree has been created with id: %s.", aziclicommon.IDText(treeObj.GetOID())), nil)
	}

	remoteInfo, err := m.cfgMgr.GetRemoteInfo(refsInfo.GetRemote())
	if err != nil {
		return failedOpErr(nil, err)
	}
	err = m.rmSrvtMgr.ReceivePack(refsInfo.GetRemote(), remoteInfo.GetPAPPort())
	if err != nil {
		return failedOpErr(nil, err)
	}

	out(nil, "", "", nil)
	for _, planObj := range plan {
		if planObj.State == azicliwkscosp.CodeObjectStateUnchanged {
			continue
		}
		out(nil, "", fmt.Sprintf("%s object with id: %s, type %s and name: %s.", aziclicommon.RemoteOperationText("Synchronizing"),
			aziclicommon.IDText(planObj.OID), aziclicommon.KeywordText(planObj.OType), aziclicommon.KeywordText(planObj.OName)), nil)
	}
	out(nil, "", "", nil)

	out(nil, "", "Apply process completed successfully.", nil)
	if !internal {
		out(nil, "", fmt.Sprintf("Your workspace is synchronized with the remote repo: %s.", aziclicommon.KeywordText(refsInfo.GetRepoURI())), nil)
	}
	return output, nil
}
