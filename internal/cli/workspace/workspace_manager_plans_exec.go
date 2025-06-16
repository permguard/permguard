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

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/workspace/cosp"
	"github.com/permguard/permguard/internal/cli/workspace/logs"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// ExecPlan generates a plan of changes to apply to the remote ledger based on the differences between the local and remote states.
func (m *WorkspaceManager) ExecPlan(out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to build the plan.", nil, true)
		return output, err
	}
	m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return fail(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return fail(nil, err)
	}
	defer fileLock.Unlock()

	return m.execInternalPlan(false, out)
}

// execInternalPlan generates a plan of changes to apply to the remote ledger based on the differences between the local and remote states.
func (m *WorkspaceManager) execInternalPlan(internal bool, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", "Failed to build the plan.", nil, true)
		}
		return output, err
	}

	// Read current head settings
	var err error
	var headCtx *currentHeadContext
	headCtx, err = m.currentHeadContext()
	if err != nil {
		return fail(nil, err)
	}

	// Executes the validation for the current head
	var output map[string]any
	output, err = m.execInternalValidate(true, out)
	if err != nil {
		output, err = fail(output, err)
		return out(output, "", fmt.Sprintf("Please execute '%s' to perform a comprehensive validation check for any potential errors.", common.CliCommandText("permguard validate")), nil, true), err
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "plan", fmt.Sprintf("Head successfully set to %s.", common.KeywordText(headCtx.Ref())), nil, true)
		out(nil, "plan", fmt.Sprintf("Ledger set to %s.", common.KeywordText(headCtx.LedgerURI())), nil, true)
	} else if m.ctx.IsVerboseJSONOutput() {
		remoteObj := map[string]any{
			"ref": headCtx.Ref(),
		}
		output = out(output, "head", remoteObj, nil, true)
		output = out(output, "ledger", headCtx.LedgerURI(), nil, true)
	}

	// Executes the planning for the current head
	out(nil, "", fmt.Sprintf("Initiating the planning process for ledger %s.", common.KeywordText(headCtx.LedgerURI())), nil, true)

	errPlanningProcessFailed := "Planning process failed."

	if headCtx.RemoteCommitID() == objects.ZeroOID {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("The ref %s has no commits associated with it.", common.KeywordText(headCtx.Ref())), nil, true)
		}
	}
	remoteTree, err := m.CurrentHeadTree(headCtx.Ref())
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("The ref %s could not read the remote tree.", common.KeywordText(headCtx.Ref())), nil, true)
		}
	}
	var remoteCodeState []cosp.CodeObjectState
	if remoteTree != nil {
		remoteCodeState, err = m.cospMgr.BuildCodeSourceCodeStateForTree(remoteTree)
		if err != nil {
			out(nil, "", errPlanningProcessFailed, nil, true)
			return fail(output, err)
		}
	} else {
		remoteCodeState = []cosp.CodeObjectState{}
	}
	localCodeState, err := m.cospMgr.ReadCodeSourceCodeState()
	if err != nil {
		out(nil, "", errPlanningProcessFailed, nil, true)
		return fail(output, err)
	}
	codeStateObjs, err := m.plan(localCodeState, remoteCodeState)
	if err != nil {
		out(nil, "", errPlanningProcessFailed, nil, true)
		return fail(output, err)
	}

	unchangedItems := []cosp.CodeObjectState{}
	createdItems := []cosp.CodeObjectState{}
	modifiedItems := []cosp.CodeObjectState{}
	deletedItems := []cosp.CodeObjectState{}
	if len(codeStateObjs) == 0 {
		out(nil, "", "No changes detected during the planning phase. system is up to date.", nil, true)
	} else {
		out(nil, "", "Planning process completed successfully.", nil, true)
		out(nil, "", "The following changes have been identified and are ready to be applied:\n", nil, true)
		unchanged, created, modified, deleted := 0, 0, 0, 0
		for _, codeStateObj := range codeStateObjs {
			if codeStateObj.State == cosp.CodeObjectStateUnchanged {
				out(nil, "", fmt.Sprintf("	%s %s %s %s", common.UnchangedText("="), common.IDText(codeStateObj.Partition), common.IDText(codeStateObj.OID), common.UnchangedText(codeStateObj.OName)), nil, true)
				unchangedItems = append(unchangedItems, codeStateObj)
				unchanged++
			}
			if codeStateObj.State == cosp.CodeObjectStateCreate {
				out(nil, "", fmt.Sprintf("	%s %s %s %s", common.CreateText("+"), common.IDText(codeStateObj.Partition), common.IDText(codeStateObj.OID), common.CreateText(codeStateObj.OName)), nil, true)
				createdItems = append(createdItems, codeStateObj)
				created++
			}
			if codeStateObj.State == cosp.CodeObjectStateModify {
				out(nil, "", fmt.Sprintf("	%s %s %s %s", common.ModifyText("~"), common.IDText(codeStateObj.Partition), common.IDText(codeStateObj.OID), common.ModifyText(codeStateObj.OName)), nil, true)
				modifiedItems = append(modifiedItems, codeStateObj)
				modified++
			}
			if codeStateObj.State == cosp.CodeObjectStateDelete {
				out(nil, "", fmt.Sprintf("	%s %s %s %s", common.DeleteText("-"), common.IDText(codeStateObj.Partition), common.IDText(codeStateObj.OID), common.DeleteText(codeStateObj.OName)), nil, true)
				deletedItems = append(deletedItems, codeStateObj)
				deleted++
			}
		}
		out(nil, "", "", nil, true)
		unchangedCountText := common.UnchangedText(fmt.Sprint(unchanged))
		createdCountText := common.CreateText(fmt.Sprint(created))
		modifiedCountText := common.ModifyText(fmt.Sprint(modified))
		deletedCountText := common.DeleteText(fmt.Sprint(deleted))
		out(nil, "", fmt.Sprintf("unchanged %s, created %s, modified %s, deleted %s", unchangedCountText, createdCountText, modifiedCountText, deletedCountText), nil, true)
		out(nil, "", "", nil, true)
		planObjs := append(createdItems, modifiedItems...)
		planObjs = append(planObjs, unchangedItems...)
		planObjs = append(planObjs, deletedItems...)
		refInfo, err := m.rfsMgr.CurrentHeadRefInfo()
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "plan", "Failed to retrieve the current head ref info.", nil, true)
			}
			out(nil, "", "Unable to build the plan.", nil, true)
			return fail(output, err)
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "plan", fmt.Sprintf("Remote for the plan is set to: %s.", common.KeywordText(refInfo.Remote())), nil, true)
			out(nil, "plan", fmt.Sprintf("Reference ID for the plan is set to: %s", common.IDText(refInfo.Ref())), nil, true)
			out(nil, "plan", "Preparing to save the plan.", nil, true)
		}
		err = m.cospMgr.SaveRemoteCodePlan(refInfo.Ref(), planObjs)
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "plan", "Failed to save the plan.", nil, true)
			}
			out(nil, "", "Unable to save the plan.", nil, true)
			return fail(output, err)
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

// ExecApply applies the plan to the remote ledger
func (m *WorkspaceManager) ExecApply(out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to apply the plan.", nil, true)
		return output, err
	}
	m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return fail(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return fail(nil, err)
	}
	defer fileLock.Unlock()

	return m.execInternalApply(false, out)
}

// execInternalApply applies the plan to the remote ledger
func (m *WorkspaceManager) execInternalApply(internal bool, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", "Failed to apply the plan.", nil, true)
		}
		return output, err
	}

	// Read current head settings
	headCtx, err := m.currentHeadContext()
	if err != nil {
		return fail(nil, err)
	}

	// Executes the plan for the current head
	output, err := m.execInternalPlan(true, out)
	if err != nil {
		return fail(nil, err)
	}

	// Executes the apply for the current head
	out(nil, "", fmt.Sprintf("Initiating the apply process for ledger %s.", common.KeywordText(headCtx.LedgerURI())), nil, true)

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", "Preparing to read the plan.", nil, true)
	}
	errPlanningProcessFailed := "Apply process failed."
	plan, err := m.cospMgr.ReadRemoteCodePlan(headCtx.Ref())
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "apply", "Failed to read the plan.", nil, true)
		}
		out(nil, "", errPlanningProcessFailed, nil, true)
		return fail(output, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", "The plan has been read successfully.", nil, true)
	}
	hasChanges := false
	for _, planItem := range plan {
		if planItem.State != cosp.CodeObjectStateUnchanged {
			hasChanges = true
			break
		}
	}
	if !hasChanges {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "apply", "No changes detected during the planning phase. system is up to date.", nil, true)
		}
		out(nil, "", "No changes detected during the planning phase. system is up to date.", nil, true)
		return output, nil
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", "Preparing to build the tree.", nil, true)
	}
	_, treeObj, err := m.buildPlanTree(plan)
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "apply", "Failed to build the tree.", nil, true)
		}
		out(nil, "", errPlanningProcessFailed, nil, true)
		return fail(output, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", fmt.Sprintf("The tree has been created with id: %s.", common.IDText(treeObj.OID())), nil, true)
	}
	commit, commitObj, err := m.buildPlanCommit(treeObj.OID(), headCtx.remoteCommitID)
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "apply", "Failed to build the commit.", nil, true)
		}
		out(nil, "", errPlanningProcessFailed, nil, true)
		return fail(output, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "apply", fmt.Sprintf("The commit has been created with id: %s.", common.IDText(commitObj.OID())), nil, true)
	}

	bag := map[string]any{
		OutFuncKey: func(key string, output string, newLine bool) {
			out(nil, key, output, nil, newLine)
		},
		LocalCodeTreeObjectKey:   treeObj,
		LocalCodeCommitKey:       commit,
		LocalCodeCommitObjectKey: commitObj,
		HeadContextKey:           headCtx,
	}

	ctx, err := m.rmSrvtMgr.NOTPPush(headCtx.Server(), headCtx.ServerPAPPort(), headCtx.ZoneID(), headCtx.LedgerID(), bag, m)
	if err != nil {
		return fail(nil, err)
	}
	committed, _ := getFromRuntimeContext[bool](ctx, CommittedKey)
	_, err = m.logsMgr.Log(headCtx.headRefInfo, headCtx.remoteCommitID, commitObj.OID(), logs.LogActionPush, committed, headCtx.LedgerURI())

	if err != nil {
		return fail(nil, err)
	}
	if !committed {
		return fail(nil, err)
	}

	_, err = m.execInternalPull(true, out)
	if err != nil {
		return fail(nil, err)
	}

	out(nil, "", "Apply process completed successfully.", nil, true)
	if !internal {
		out(nil, "", fmt.Sprintf("Your workspace is synchronized with the remote ledger: %s.", common.KeywordText(headCtx.LedgerURI())), nil, true)
	}
	return output, nil
}
