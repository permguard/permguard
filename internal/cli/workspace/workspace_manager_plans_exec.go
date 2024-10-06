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

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscosp "github.com/permguard/permguard/internal/cli/workspace/cosp"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// ExecPlan generates a plan of changes to apply to the remote repo based on the differences between the local and remote states.
func (m *WorkspaceManager) ExecPlan(out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	return m.execInternalPlan(false, out)
}

// execInternalPlan generates a plan of changes to apply to the remote repo based on the differences between the local and remote states.
func (m *WorkspaceManager) execInternalPlan(internal bool, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to build the plan.", nil, true)
		return output, err
	}

	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	// Read current head settings
	headRefs, err := m.rfsMgr.GetCurrentHeadRefs()
	if err != nil || headRefs == "" {
		out(nil, "", "Please ensure a valid remote repo is checked out.", nil, true)
		if err == nil {
			err = azerrors.WrapSystemError(azerrors.ErrCliWorkspace, "cli: invalid head refs")
		}
		return failedOpErr(nil, err)
	}
	headRefsInfo, err := m.rfsMgr.GetCurrentHeadRefsInfo()
	if err != nil {
		return failedOpErr(nil, err)
	}
	repoURI := headRefsInfo.GetRepoURI()

	// Executes the validation for the current head

	output, err := m.execInternalValidate(true, out)
	if err != nil {
		return failedOpErr(output, err)
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "plan", fmt.Sprintf("Head successfully set to %s.", aziclicommon.KeywordText(headRefs)), nil, true)
		out(nil, "plan", fmt.Sprintf("Repo set to %s.", aziclicommon.KeywordText(repoURI)), nil, true)
	} else if m.ctx.IsVerboseJSONOutput() {
		remoteObj := map[string]any{
			"refs": headRefs,
		}
		output = out(output, "head", remoteObj, nil, true)
		output = out(output, "repo", repoURI, nil, true)
	}

	// Executes the planning for the current head

	out(nil, "", fmt.Sprintf("Initiating the planning process for repo %s.", aziclicommon.KeywordText(repoURI)), nil, true)

	errPlanningProcessFailed := "Planning process failed."

	commit, err := m.rfsMgr.GetRefsCommit(headRefs)
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("Unable to read the commit for refs %s.", aziclicommon.KeywordText(headRefs)), nil, true)
		}
		out(nil, "", errPlanningProcessFailed, nil, true)
		return failedOpErr(nil, err)
	}

	var remoteCodeState []azicliwkscosp.CodeObjectState = nil
	if commit == azlangobjs.ZeroOID {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("The refs %s has no commits associated with it.", aziclicommon.KeywordText(headRefs)), nil, true)
		}
	}

	localCodeState, err := m.cospMgr.ReadCodeSourceCodeState()
	if err != nil {
		out(nil, "", errPlanningProcessFailed, nil, true)
		return failedOpErr(output, err)
	}
	codeStateObjs, err := m.plan(localCodeState, remoteCodeState)
	if err != nil {
		out(nil, "", errPlanningProcessFailed, nil, true)
		return failedOpErr(output, err)
	}

	unchangedItems := []azicliwkscosp.CodeObjectState{}
	createdItems := []azicliwkscosp.CodeObjectState{}
	modifiedItems := []azicliwkscosp.CodeObjectState{}
	deletedItems := []azicliwkscosp.CodeObjectState{}
	if len(codeStateObjs) == 0 {
		out(nil, "", "No changes detected during the planning phase. system is up to date.", nil, true)
	} else {
		out(nil, "", "Planning process completed successfully.", nil, true)
		out(nil, "", "The following changes have been identified and are ready to be applied:\n", nil, true)
		for _, codeStateObj := range codeStateObjs {
			if codeStateObj.State == azicliwkscosp.CodeObjectStateUnchanged {
				out(nil, "", fmt.Sprintf("	%s %s %s", aziclicommon.UnchangedText("="), aziclicommon.IDText(codeStateObj.OID), aziclicommon.UnchangedText(codeStateObj.OName)), nil, true)
				unchangedItems = append(unchangedItems, codeStateObj)
			}
			if codeStateObj.State == azicliwkscosp.CodeObjectStateCreate {
				out(nil, "", fmt.Sprintf("	%s %s %s", aziclicommon.CreateText("+"), aziclicommon.IDText(codeStateObj.OID), aziclicommon.CreateText(codeStateObj.OName)), nil, true)
				createdItems = append(createdItems, codeStateObj)
			}
			if codeStateObj.State == azicliwkscosp.CodeObjectStateModify {
				out(nil, "", fmt.Sprintf("	%s %s %s", aziclicommon.ModifyText("~"), aziclicommon.IDText(codeStateObj.OID), aziclicommon.ModifyText(codeStateObj.OName)), nil, true)
				modifiedItems = append(modifiedItems, codeStateObj)
			}
			if codeStateObj.State == azicliwkscosp.CodeObjectStateDelete {
				out(nil, "", fmt.Sprintf("	%s %s %s", aziclicommon.DeleteText("-"), aziclicommon.IDText(codeStateObj.OID), aziclicommon.DeleteText(codeStateObj.OName)), nil, true)
				deletedItems = append(deletedItems, codeStateObj)
			}
		}
		out(nil, "", "", nil, true)
		planObjs := append(createdItems, modifiedItems...)
		planObjs = append(planObjs, unchangedItems...)
		refsInfo, err := m.rfsMgr.GetCurrentHeadRefsInfo()
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "plan", "Failed to retrieve the current head refs info.", nil, true)
			}
			out(nil, "", "Unable to build the plan.", nil, true)
			return failedOpErr(output, err)
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("Remote for the plan is set to: %s.", aziclicommon.KeywordText(refsInfo.GetRemote())), nil, true)
			out(nil, "plan", fmt.Sprintf("Reference ID for the plan is set to: %s", aziclicommon.IDText(refsInfo.GetRefID())), nil, true)
			out(nil, "plan", "Preparing to save the plan.", nil, true)
		}
		err = m.cospMgr.SaveRemoteCodePlan(refsInfo.GetRemote(), refsInfo.GetRefID(), planObjs)
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "plan", "Failed to save the plan.", nil, true)
			}
			out(nil, "", "Unable to save the plan.", nil, true)
			return failedOpErr(output, err)
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", "Plan saved successfully.", nil, true)
		}
		if !internal {
			out(nil, "", "Run the 'apply' command to apply the changes.", nil, true)
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
func (m *WorkspaceManager) ExecApply(out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	return m.execInternalApply(false, out)
}

// execInternalApply applies the plan to the remote repo
func (m *WorkspaceManager) execInternalApply(internal bool, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to apply the plan.", nil, true)
		return output, err
	}

	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	// Read current head settings
	headRefs, err := m.rfsMgr.GetCurrentHeadRefs()
	headRefsInfo, err := m.rfsMgr.GetCurrentHeadRefsInfo()
	if err != nil {
		return failedOpErr(nil, err)
	}

	remoteInfo, err := m.cfgMgr.GetRemoteInfo(headRefsInfo.GetRemote())
	if err != nil {
		return failedOpErr(nil, err)
	}

	repoURI := headRefsInfo.GetRepoURI()
	remote := headRefsInfo.GetRemote()
	accountID := headRefsInfo.GetAccountID()
	refID := headRefsInfo.GetRefID()
	repoID, err := m.rfsMgr.GetRefsRepoID(headRefs)
	if err != nil {
		return failedOpErr(nil, err)
	}
	server := remoteInfo.GetServer()
	serverPAPPort := remoteInfo.GetPAPPort()

	// Executes the plan for the current head

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

	// Executes the apply for the current head

	out(nil, "", fmt.Sprintf("Initiating the apply process for repo %s.", aziclicommon.KeywordText(repoURI)), nil, true)

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", "Preparing to read the plan.", nil, true)
	}
	errPlanningProcessFailed := "Apply process failed."
	plan, err := m.cospMgr.ReadRemoteCodePlan(remote, refID)
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "apply", "Failed to read the plan.", nil, true)
		}
		out(nil, "", errPlanningProcessFailed, nil, true)
		return failedOpErr(output, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", "The plan has been read successfully.", nil, true)
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", "Preparing to build the tree.", nil, true)
	}
	_, treeObj, err := m.buildPlanTree(plan, absLang)
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "apply", "Failed to build the tree.", nil, true)
		}
		out(nil, "", errPlanningProcessFailed, nil, true)
		return failedOpErr(output, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", fmt.Sprintf("The tree has been created with id: %s.", aziclicommon.IDText(treeObj.GetOID())), nil, true)
	}

	err = m.rmSrvtMgr.NOTPPush(server, serverPAPPort, accountID, repoID, m)
	if err != nil {
		return failedOpErr(nil, err)
	}

	out(nil, "", "", nil, true)
	for _, planObj := range plan {
		if planObj.State == azicliwkscosp.CodeObjectStateUnchanged {
			continue
		}
		out(nil, "", fmt.Sprintf("%s object with id: %s, type %s and name: %s.", aziclicommon.RemoteOperationText("Synchronizing"),
			aziclicommon.IDText(planObj.OID), aziclicommon.KeywordText(planObj.OType), aziclicommon.KeywordText(planObj.OName)), nil, true)
	}
	out(nil, "", "", nil, true)

	out(nil, "", "Apply process completed successfully.", nil, true)
	if !internal {
		out(nil, "", fmt.Sprintf("Your workspace is synchronized with the remote repo: %s.", aziclicommon.KeywordText(repoURI)), nil, true)
	}
	return output, nil
}
