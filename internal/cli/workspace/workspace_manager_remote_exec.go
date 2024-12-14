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
	"strings"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azlangtypes "github.com/permguard/permguard-abs-language/pkg/languages/types"
	azfiles "github.com/permguard/permguard-core/pkg/extensions/files"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	azicliwkslogs "github.com/permguard/permguard/internal/cli/workspace/logs"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// CodeGenFileName is the name of the codegen file.
	CodeGenFileName = "codegen"
	// OriginRemoteName is the name of the origin remote.
	OriginRemoteName = "origin"
)

// execInternalCheckoutRepo checks out a repository.
func (m *WorkspaceManager) execInternalCheckoutRepo(internal bool, repoURI string, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", fmt.Sprintf("Failed to check out the repository %s.", aziclicommon.KeywordText(repoURI)), nil, true)
		}
		return output, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Initiating remote verification process.", nil, true)
	}

	// Verifies the repository URI and check if it already exists
	repoInfo, err := azicliwkscommon.GetRepoInfoFromURI(repoURI)
	if err != nil {
		return failedOpErr(nil, err)
	}
	var output map[string]any
	if ok := m.cfgMgr.CheckRepoIfExists(repoURI); !ok {
		// Retrieves the remote information
		remoteInfo, err := m.cfgMgr.GetRemoteInfo(repoInfo.GetRemote())
		if err != nil {
			return failedOpErr(nil, err)
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Retrieving remote repository information.", nil, true)
		}
		srvRepo, err := m.rmSrvtMgr.GetServerRemoteRepo(remoteInfo, repoInfo)
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "checkout", "Failed to retrieve remote repository information.", nil, true)
			}
			return failedOpErr(nil, err)
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Remote repository retrieved successfully.", nil, true)
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Remote verified successfully.", nil, true)
		}
		// Add the repository
		ref := m.rfsMgr.GenerateRef(repoInfo.GetRemote(), repoInfo.GetAccountID(), srvRepo.RepositoryID)
		output, err = m.cfgMgr.ExecAddRepo(repoURI, ref, repoInfo.GetRemote(), repoInfo.GetRepo(), srvRepo.RepositoryID, repoInfo.GetAccountID(), nil, out)
		if err != nil && !azerrors.AreErrorsEqual(err, azerrors.ErrCliRecordExists) {
			return failedOpErr(output, err)
		}
		// Checkout the head
		remoteCommitID := azlangobjs.ZeroOID
		var remoteRef, headRef string
		remoteRef, headRef, output, err = m.rfsMgr.ExecCheckoutRefFilesForRemote(repoInfo.GetRemote(), repoInfo.GetAccountID(), repoInfo.GetRepo(), srvRepo.RepositoryID, remoteCommitID, output, out)
		if err != nil {
			return failedOpErr(nil, err)
		}
		// Read current remote ref info
		remoteRefInfo, err := m.rfsMgr.GetRefInfo(remoteRef)
		if err != nil {
			return failedOpErr(nil, err)
		}
		_, err = m.logsMgr.Log(remoteRefInfo, remoteCommitID, remoteCommitID, azicliwkslogs.LogActionCheckout, true, remoteRef)
		if err != nil {
			return failedOpErr(nil, err)
		}
		// Read current head ref info
		headRefInfo, err := m.rfsMgr.GetRefInfo(headRef)
		if err != nil {
			return failedOpErr(nil, err)
		}
		_, err = m.logsMgr.Log(headRefInfo, remoteCommitID, remoteCommitID, azicliwkslogs.LogActionCheckout, true, remoteRef)
		if err != nil {
			return failedOpErr(nil, err)
		}
	}

	refInfo, err := m.cfgMgr.GetRepoInfo(repoURI)
	if err != nil {
		return failedOpErr(nil, err)
	}
	remoteRef := azicliwkscommon.GenerateHeadRef(refInfo.GetAccountID(), refInfo.GetRepo())
	_, output, err = m.rfsMgr.ExecCheckoutHead(remoteRef, output, out)
	if err != nil {
		return failedOpErr(nil, err)
	}

	_, err = m.execInternalPull(true, out)
	if err != nil {
		return failedOpErr(nil, err)
	}

	return output, nil
}

// ExecCheckoutRepo checks out a repository.
func (m *WorkspaceManager) ExecCheckoutRepo(repoURI string, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to checkout the repository %s.", aziclicommon.KeywordText(repoURI)), nil, true)
		return output, err
	}
	m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	return m.execInternalCheckoutRepo(false, repoURI, out)
}

func (m *WorkspaceManager) execInternalPull(internal bool, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", "Failed to pull changes from the remote repository.", nil, true)
		}
		return output, err
	}

	output, _ := m.execInternalRefresh(true, out)

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
	headRefInfo := headCtx.headRefInfo
	remoteRefInfo := headCtx.remoteRefInfo
	if err != nil {
		return failedOpErr(nil, err)
	}

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "pull", "Preparing to pull changes from the remote repository.", nil, true)
	}

	bag := map[string]any{
		OutFuncKey: func(key string, output string, newLine bool) {
			out(nil, key, output, nil, newLine)
		},
		LanguageAbstractionKey: absLang,
		LocalCodeCommitIDKey:   headCtx.remoteCommitID,
		HeadContextKey:         headCtx,
	}

	ctx, err := m.rmSrvtMgr.NOTPPull(headCtx.GetServer(), headCtx.GetServerPAPPort(), headCtx.GetAccountID(), headCtx.GetRepoID(), bag, m)
	if err != nil {
		return failedOpErr(nil, err)
	}

	localCommitID, _ := getFromRuntimeContext[string](ctx, LocalCodeCommitIDKey)
	localCommitsCount, _ := getFromRuntimeContext[uint32](ctx, LocalCommitsCountKey)
	remoteCommitID, _ := getFromRuntimeContext[string](ctx, RemoteCommitIDKey)
	remoteCommitCount, _ := getFromRuntimeContext[uint32](ctx, RemoteCommitsCountKey)
	if localCommitID == remoteCommitID {
		if m.ctx.IsTerminalOutput() {
			out(nil, "", "The local workspace is already fully up to date with the remote repository.", nil, true)
		}
	} else if localCommitsCount != remoteCommitCount {
		if m.ctx.IsTerminalOutput() {
			out(nil, "", "Not all commits were successfully pulled. Please retry the operation.", nil, true)
		}
		return failedOpErr(nil, azerrors.WrapSystemError(azerrors.ErrCliRecordExists, "Not all commits were successfully pulled."))
	} else {
		committed, _ := getFromRuntimeContext[bool](ctx, CommittedKey)
		if !committed || localCommitID == "" || remoteCommitID == "" {
			if localCommitID != "" && remoteCommitID != "" {
				_, err := m.logsMgr.Log(remoteRefInfo, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, false, remoteRefInfo.GetRepoURI())
				if err != nil {
					return failedOpErr(nil, err)
				}
			}
		}
		err = m.rfsMgr.SaveRefConfig(remoteRefInfo.GetRepoID(), remoteRefInfo.GetRef(), remoteCommitID)
		if err != nil {
			_, err = m.logsMgr.Log(remoteRefInfo, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, false, remoteRefInfo.GetRepoURI())
			if err != nil {
				return failedOpErr(nil, err)
			}
			return failedOpErr(nil, err)
		}
		err = m.rfsMgr.SaveRefWithRemoteConfig(headRefInfo.GetRepoID(), headRefInfo.GetRef(), remoteRefInfo.GetRef(), remoteCommitID)
		if err != nil {
			_, err = m.logsMgr.Log(headRefInfo, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, false, remoteRefInfo.GetRepoURI())
			if err != nil {
				return failedOpErr(nil, err)
			}
			return failedOpErr(nil, err)
		}
		_, err = m.logsMgr.Log(remoteRefInfo, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, true, remoteRefInfo.GetRepoURI())
		if err != nil {
			return failedOpErr(nil, err)
		}
		_, err = m.logsMgr.Log(headRefInfo, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, true, remoteRefInfo.GetRepoURI())
		if err != nil {
			return failedOpErr(nil, err)
		}
	}
	if remoteCommitID != azlangobjs.ZeroOID {
		commitObj, err := m.cospMgr.ReadObject(remoteCommitID)
		if err != nil {
			return failedOpErr(nil, err)
		}
		commit, err := absLang.ConvertObjectToCommit(commitObj)

		treeObj, err := m.cospMgr.ReadObject(commit.GetTree())
		if err != nil {
			return failedOpErr(nil, err)
		}
		tree, err := absLang.ConvertObjectToTree(treeObj)

		codeMap, err := m.cospMgr.ReadCodeSourceCodeMap()
		if err != nil {
			return failedOpErr(nil, err)
		}
		codeMapIds := make(map[string]bool)
		for _, code := range codeMap {
			codeMapIds[code.OID] = true
		}

		var schemaBlock []byte
		codeBlocks := [][]byte{}
		for _, entry := range tree.GetEntries() {
			if _, ok := codeMapIds[entry.GetOID()]; !ok {
				entryObj, err := m.cospMgr.ReadObject(entry.GetOID())
				if err != nil {
					return failedOpErr(nil, err)
				}
				classType, codeBlock, err := absLang.ReadPolicyBlobContentBytes(entryObj)
				if err != nil {
					return failedOpErr(nil, err)
				}
				switch classType {
				case azlangtypes.ClassTypeSchema:
					schemaBlock = codeBlock
				default:
					codeBlocks = append(codeBlocks, codeBlock)
				}
			}
		}
		if len(codeBlocks) > 0 {
			codeBlock, ext, err := absLang.CreateMultiPolicyContentBytes(codeBlocks)
			if err != nil {
				return failedOpErr(nil, err)
			}
			fileName, err := azfiles.GenerateUniqueFile(CodeGenFileName, ext)
			if err != nil {
				return failedOpErr(nil, err)
			}
			m.persMgr.WriteFile(azicliwkspers.WorkspaceDir, fileName, codeBlock, 0644, false)
		}
		if schemaBlock != nil {
			langSpec := absLang.GetLanguageSpecification()
			schemaFileNames := langSpec.GetSupportedSchemaFileNames()
			if len(schemaFileNames) < 1 {
				return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: no schema file names are supported")
			}
			schemaFileName := schemaFileNames[0]
			m.persMgr.WriteFile(azicliwkspers.WorkspaceDir, schemaFileName, schemaBlock, 0644, false)
		}
	}

	m.cospMgr.CleanCodeSource()

	if !internal {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, azicliwkslogs.LogActionPull, "The pull has been completed successfully.", nil, true)
		}
		out(nil, "", "Pull process completed successfully.", nil, true)
		out(nil, "", fmt.Sprintf("Your workspace is synchronized with the remote repository: %s.", aziclicommon.KeywordText(headCtx.GetRepoURI())), nil, true)
	}
	return output, nil
}

// ExecPull fetches the latest changes from the remote repository and constructs the remote state.
func (m *WorkspaceManager) ExecPull(out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to pull changes from the remote repository.", nil, true)
		return output, err
	}
	m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	return m.execInternalPull(false, out)
}

// ExecCloneRepo clones a repository.
func (m *WorkspaceManager) ExecCloneRepo(language, repoURI string, aapPort, papPort int, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to clone the repository %s.", aziclicommon.KeywordText(repoURI)), nil, true)
		return output, err
	}
	m.ExecPrintContext(nil, out)

	var output map[string]any
	repoURI = strings.ToLower(repoURI)
	if !strings.HasPrefix(repoURI, "permguard@") {
		return failedOpErr(output, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid repository URI"))
	}
	repoURI = strings.TrimPrefix(repoURI, "permguard@")
	elements := strings.Split(repoURI, "/")
	if len(elements) != 3 {
		return failedOpErr(output, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid repository URI"))
	}

	uriServer := elements[0]
	uriAccountID := elements[1]
	uriRepo := elements[2]

	output, err := m.ExecInitWorkspace(language, out)
	aborted := false
	if err == nil {
		fileLock, err := m.tryLock()
		if err != nil {
			return failedOpErr(nil, err)
		}
		defer fileLock.Unlock()
		output, err = m.execInternalAddRemote(true, OriginRemoteName, uriServer, aapPort, papPort, out)
		if err == nil {
			repoURI := fmt.Sprintf("%s/%s/%s", OriginRemoteName, uriAccountID, uriRepo)
			output, err = m.execInternalCheckoutRepo(true, repoURI, out)
			if err != nil {
				aborted = true
			}
		} else {
			aborted = true
		}
	}
	if aborted {
		return failedOpErr(output, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: operation has been aborted"))
	}
	return output, nil
}
