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
	//"encoding/json"
	"fmt"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkslogs "github.com/permguard/permguard/internal/cli/workspace/logs"
	azicliwksrepos "github.com/permguard/permguard/internal/cli/workspace/repos"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// ExecCheckoutRepo checks out a repository.
func (m *WorkspaceManager) ExecCheckoutRepo(repoURI string, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to checkout repo %s.", aziclicommon.KeywordText(repoURI)), nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	repoInfo, err := azicliwksrepos.GetRepoInfoFromURI(repoURI)
	if err != nil {
		return failedOpErr(nil, err)
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Initiating remote verification process.", nil, true)
	}
	exist, _ := m.cfgMgr.CheckRepoIfExists(repoURI)
	if exist {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Remote verification failed: repository already exists.", nil, true)
		}
		return failedOpErr(nil, azerrors.WrapSystemError(azerrors.ErrCliRecordExists, fmt.Sprintf("cli: repo %s already exists", repoURI)))
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Remote verified successfully.", nil, true)
	}

	remoteInfo, err := m.cfgMgr.GetRemoteInfo(repoInfo.GetRemote())
	if err != nil {
		return failedOpErr(nil, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Retrieving remote repository information.", nil, true)
	}
	srvRepo, err := m.rmSrvtMgr.GetServerRemoteRepo(repoInfo.GetAccountID(), repoInfo.GetRepo(), remoteInfo.GetServer(), remoteInfo.GetAAPPort(), remoteInfo.GetPAPPort())
	if err != nil {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Failed to retrieve remote repository information.", nil, true)
		}
		return failedOpErr(nil, err)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Remote repository retrieved successfully.", nil, true)
	}
	remoteRefs := azlangobjs.ZeroOID
	headInfo, output, err := m.rfsMgr.ExecCheckoutHead(repoInfo.GetRemote(), repoInfo.GetAccountID(), repoInfo.GetRepo(), srvRepo.RepositoryID, remoteRefs, nil, out)
	if err != nil {
		return failedOpErr(nil, err)
	}
	output, err = m.cfgMgr.ExecAddRepo(headInfo.GetRefs(), repoURI, output, out)
	if err != nil && !azerrors.AreErrorsEqual(err, azerrors.ErrCliRecordExists) {
		return failedOpErr(output, err)
	}
	_, err = m.logsMgr.Log(repoInfo.GetRemote(), headInfo.GetRefs(), remoteRefs, remoteRefs, azicliwkslogs.LogActionCheckout, true, repoURI)
	if err != nil {
		return failedOpErr(nil, err)
	}
	return output, nil
}

// ExecPull fetches the latest changes from the remote repository and constructs the remote state.
func (m *WorkspaceManager) ExecPull(out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to pull changes from the remote repo.", nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	output, _ = m.execInternalRefresh(true, out)

	// Creates the abstraction for the language
	lang, err := m.cfgMgr.GetLanguage()
	if err != nil {
		return failedOpErr(nil, err)
	}
	absLang, err := m.langFct.CreateLanguageAbastraction(lang)
	if err != nil {
		return failedOpErr(nil, err)
	}

	// Read current head settings
	headCtx, err := m.getCurrentHeadContext()
	if err != nil {
		return failedOpErr(nil, err)
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "pull", "Preparing to pull changes from the remote repo.", nil, true)
	}

	bag := map[string]any{
		OutFuncKey: func(key string, output string, newLine bool) {
			out(nil, key, output, nil, newLine)
		},
		LanguageAbstractionKey:   absLang,
		LocalCodeCommitIDKey:     headCtx.commitID,
		HeadContextKey:           headCtx,
	}

	ctx, err := m.rmSrvtMgr.NOTPPull(headCtx.GetServer(), headCtx.GetServerPAPPort(), headCtx.GetAccountID(), headCtx.GetRepoID(), bag, m)
	if err != nil {
		return failedOpErr(nil, err)
	}

	localCommitID, _ := getFromRuntimeContext[string](ctx, LocalCodeCommitIDKey)
	remoteCommitID, _ := getFromRuntimeContext[string](ctx, RemoteCommitIDKey)
	if localCommitID == remoteCommitID {
		if m.ctx.IsTerminalOutput() {
			out(nil, "", "The local workspace is already fully up to date with the remote repository.", nil, true)
		}
	} else {
		committed, _ := getFromRuntimeContext[bool](ctx, CommittedKey)
		if !committed || localCommitID == "" || remoteCommitID == "" {
			if localCommitID != "" && remoteCommitID != "" {
				_, err := m.logsMgr.Log(headCtx.remote, headCtx.refs, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, false, headCtx.repoURI)
				if err != nil {
					return failedOpErr(nil, err)
				}
			}
		}
		err = m.rfsMgr.SaveRefsConfig(headCtx.repoID, headCtx.refs, remoteCommitID)
		if err != nil {
			_, err = m.logsMgr.Log(headCtx.remote, headCtx.refs, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, false, headCtx.repoURI)
			if err != nil {
				return failedOpErr(nil, err)
			}
			return failedOpErr(nil, err)
		}
		_, err = m.logsMgr.Log(headCtx.remote, headCtx.refs, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, true, headCtx.repoURI)
		if err != nil {
			return failedOpErr(nil, err)
		}
	}
	codeMap, err := m.cospMgr.ReadCodeSourceCodeMap()
	if err != nil {
		return failedOpErr(nil, err)
	}
	codeMapIds := make(map[string]bool)
	for _, code := range codeMap {
		codeMapIds[code.OID] = true
	}

	commitObj, err := m.cospMgr.ReadObject(remoteCommitID)
	if err != nil {
		return failedOpErr(nil, err)
	}
	commit, err := absLang.GetCommitObject(commitObj)

	treeObj, err := m.cospMgr.ReadObject(commit.GetTree())
	if err != nil {
		return failedOpErr(nil, err)
	}
	tree, err := absLang.GetTreeeObject(treeObj)

	msCodeMap := make(map[string][]byte)
	for _, entry := range tree.GetEntries() {
		if _, ok := codeMapIds[entry.GetOID()]; !ok {
			entryObj, err := m.cospMgr.ReadObject(entry.GetOID())
			absLang.GetCommitObject(entryObj)
			if err != nil {
				return failedOpErr(nil, err)
			}
			msCodeMap[entry.GetOID()] = entryObj.GetContent()
		}
	}

	for item := range msCodeMap {
		obmgr, _ := azlangobjs.NewObjectManager()
		obj, _ := obmgr.DeserializeObjectFromBytes(msCodeMap[item])
		objInfo, _ := obmgr.GetObjectInfo(obj)
		objInstance := objInfo.GetInstance()
		out(nil, "", fmt.Sprintf("%s",objInstance), nil, true)
		//out(nil, "", fmt.Sprintf("%s",string(msCodeMap[item])), nil, true)
	}

	m.cospMgr.CleanCodeSource()

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, azicliwkslogs.LogActionPull, "The pull has been completed successfully.", nil, true)
	}
	out(nil, "", "Pull process completed successfully.", nil, true)
	out(nil, "", fmt.Sprintf("Your workspace is synchronized with the remote repo: %s.", aziclicommon.KeywordText(headCtx.GetRepoURI())), nil, true)
	return output, nil
}
