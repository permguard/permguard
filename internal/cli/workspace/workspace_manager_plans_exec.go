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
)

// ExecPlan generates a plan of changes to apply to the remote repository based on the differences between the local and remote states.
func (m *WorkspaceManager) ExecPlan(out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	return m.execInternalPlan(false, out)
}

// execInternalPlan generates a plan of changes to apply to the remote repository based on the differences between the local and remote states.
func (m *WorkspaceManager) execInternalPlan(internal bool, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to build the plan.", nil, true)
		return output, err
	}

	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	// Read current head settings
	headCtx, err := m.getCurrentHeadContext()
	if err != nil {
		return failedOpErr(nil, err)
	}

	// Executes the validation for the current head
	output, err := m.execInternalValidate(true, out)
	if err != nil {
		return failedOpErr(output, err)
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "plan", fmt.Sprintf("Head successfully set to %s.", aziclicommon.KeywordText(headCtx.GetRefs())), nil, true)
		out(nil, "plan", fmt.Sprintf("Repo set to %s.", aziclicommon.KeywordText(headCtx.GetRepoURI())), nil, true)
	} else if m.ctx.IsVerboseJSONOutput() {
		remoteObj := map[string]any{
			"refs": headCtx.GetRefs(),
		}
		output = out(output, "head", remoteObj, nil, true)
		output = out(output, "repo", headCtx.GetRepoURI(), nil, true)
	}

	// Executes the planning for the current head
	out(nil, "", fmt.Sprintf("Initiating the planning process for repo %s.", aziclicommon.KeywordText(headCtx.GetRepoURI())), nil, true)

	errPlanningProcessFailed := "Planning process failed."

	var remoteCodeState []azicliwkscosp.CodeObjectState = nil
	if headCtx.GetCommit() == azlangobjs.ZeroOID {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("The refs %s has no commits associated with it.", aziclicommon.KeywordText(headCtx.GetRefs())), nil, true)
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
	headCtx, err := m.getCurrentHeadContext()
	if err != nil {
		return failedOpErr(nil, err)
	}

	// Executes the plan for the current head
	output, err := m.execInternalPlan(true, out)
	if err != nil {
		return failedOpErr(nil, err)
	}

	// Creates the abstraction for the language
	lang, err := m.cfgMgr.GetLanguage()
	if err != nil {
		return failedOpErr(nil, err)
	}
	absLang, err := m.langFct.CreateLanguageAbastraction(lang)
	if err != nil {
		return failedOpErr(nil, err)
	}

	// Executes the apply for the current head
	out(nil, "", fmt.Sprintf("Initiating the apply process for repo %s.", aziclicommon.KeywordText(headCtx.GetRepoURI())), nil, true)

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", "Preparing to read the plan.", nil, true)
	}
	errPlanningProcessFailed := "Apply process failed."
	plan, err := m.cospMgr.ReadRemoteCodePlan(headCtx.GetRemote(), headCtx.GetRefID())
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
	headTreeID := azlangobjs.ZeroOID
	if headCtx.commitID != azlangobjs.ZeroOID {
		headCommitObj, err := m.cospMgr.ReadObject(headCtx.commitID)
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "apply", "Failed to read the head commit.", nil, true)
			}
			out(nil, "", errPlanningProcessFailed, nil, true)
			return failedOpErr(output, err)
		}
		headCommit, err := absLang.GetCommitObject(headCommitObj)
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "apply", "Failed to get the head commit.", nil, true)
			}
			out(nil, "", errPlanningProcessFailed, nil, true)
			return failedOpErr(output, err)
		}
		headTreeID = headCommit.GetTree()
	}
	commit, commitObj, err := m.buildPlanCommit(treeObj.GetOID(), headTreeID, absLang)
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "apply", "Failed to build the commit.", nil, true)
		}
		out(nil, "", errPlanningProcessFailed, nil, true)
		return failedOpErr(output, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", fmt.Sprintf("The commit has been created with id: %s.", aziclicommon.IDText(commitObj.GetOID())), nil, true)
	}

	bag := map[string]any{
		OutFuncKey: func(key string, output string, newLine bool) {
			out(nil, key, output, nil, newLine)
		},
		LanguageAbstractionKey:   absLang,
		LocalCodeTreeObjectKey:   treeObj,
		LocalCodeCommitKey:       commit,
		LocalCodeCommitObjectKey: commitObj,
		HeadContextKey:           headCtx,
	}
	err = m.rmSrvtMgr.NOTPPush(headCtx.GetServer(), headCtx.GetServerPAPPort(), headCtx.GetAccountID(), headCtx.GetRepoID(), bag, m)
	if err != nil {
		return failedOpErr(nil, err)
	}

	out(nil, "", "Apply process completed successfully.", nil, true)
	if !internal {
		out(nil, "", fmt.Sprintf("Your workspace is synchronized with the remote repo: %s.", aziclicommon.KeywordText(headCtx.GetRepoURI())), nil, true)
	}
	return output, nil
}
