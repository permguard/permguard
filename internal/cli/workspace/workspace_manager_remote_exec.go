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

	azauthzlangtypes "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar/authstarmodels/authz/languages/types"
	azobjs "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar/authstarmodels/objects"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
	azicliwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	azicliwkslogs "github.com/permguard/permguard/internal/cli/workspace/logs"
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azfiles "github.com/permguard/permguard/pkg/core/files"
)

const (
	// CodeGenFileName is the name of the codegen file.
	CodeGenFileName = "codegen"
	// OriginRemoteName is the name of the origin remote.
	OriginRemoteName = "origin"
)

// execInternalCheckoutLedger checks out a ledger.
func (m *WorkspaceManager) execInternalCheckoutLedger(internal bool, ledgerURI string, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", fmt.Sprintf("Failed to check out the ledger %s.", aziclicommon.KeywordText(ledgerURI)), nil, true)
		}
		return output, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Initiating remote verification process.", nil, true)
	}

	// Verifies the ledger URI and check if it already exists
	ledgerInfo, err := azicliwkscommon.GetLedgerInfoFromURI(ledgerURI)
	if err != nil {
		return failedOpErr(nil, err)
	}
	var output map[string]any
	if ok := m.cfgMgr.CheckLedgerIfExists(ledgerURI); !ok {
		// Retrieves the remote information
		remoteInfo, err := m.cfgMgr.GetRemoteInfo(ledgerInfo.GetRemote())
		if err != nil {
			return failedOpErr(nil, err)
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Retrieving remote ledger information.", nil, true)
		}
		srvLedger, err := m.rmSrvtMgr.GetServerRemoteLedger(remoteInfo, ledgerInfo)
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "checkout", "Failed to retrieve remote ledger information.", nil, true)
			}
			return failedOpErr(nil, err)
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Remote ledger retrieved successfully.", nil, true)
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Remote verified successfully.", nil, true)
		}
		// Add the ledger
		ref := m.rfsMgr.GenerateRef(ledgerInfo.GetRemote(), ledgerInfo.GetZoneID(), srvLedger.LedgerID)
		output, err = m.cfgMgr.ExecAddLedger(ledgerURI, ref, ledgerInfo.GetRemote(), ledgerInfo.GetLedger(), srvLedger.LedgerID, ledgerInfo.GetZoneID(), nil, out)
		if err != nil && !azerrors.AreErrorsEqual(err, azerrors.ErrCliRecordExists) {
			return failedOpErr(output, err)
		}
		// Checkout the head
		remoteCommitID := azobjs.ZeroOID
		var remoteRef, headRef string
		remoteRef, headRef, output, err = m.rfsMgr.ExecCheckoutRefFilesForRemote(ledgerInfo.GetRemote(), ledgerInfo.GetZoneID(), ledgerInfo.GetLedger(), srvLedger.LedgerID, remoteCommitID, output, out)
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

	refInfo, err := m.cfgMgr.GetLedgerInfo(ledgerURI)
	if err != nil {
		return failedOpErr(nil, err)
	}
	remoteRef := azicliwkscommon.GenerateHeadRef(refInfo.GetZoneID(), refInfo.GetLedger())
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

// ExecCheckoutLedger checks out a ledger.
func (m *WorkspaceManager) ExecCheckoutLedger(ledgerURI string, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to checkout the ledger %s.", aziclicommon.KeywordText(ledgerURI)), nil, true)
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

	return m.execInternalCheckoutLedger(false, ledgerURI, out)
}

// execInternalPull executes an internal pull.
func (m *WorkspaceManager) execInternalPull(internal bool, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", "Failed to pull changes from the remote ledger.", nil, true)
		}
		return output, err
	}

	m.execInternalRefresh(true, out)

	// TODO: Read the language from the authz-model manifest
	// Creates the abstraction for the language
	// lang, err := m.cfgMgr.GetLanguage()
	// if err != nil {
	// 	return failedOpErr(nil, err)
	// }
	lang := "cedar"
	absLang, err := m.langFct.GetLanguageAbastraction(lang)
	if err != nil {
		return failedOpErr(nil, err)
	}

	output := map[string]any{}

	// Read current head settings
	headCtx, err := m.getCurrentHeadContext()
	if err != nil {
		return failedOpErr(nil, err)
	}
	headRefInfo := headCtx.headRefInfo
	remoteRefInfo := headCtx.remoteRefInfo

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "pull", "Preparing to pull changes from the remote ledger.", nil, true)
	}

	bag := map[string]any{
		OutFuncKey: func(key string, output string, newLine bool) {
			out(nil, key, output, nil, newLine)
		},
		LanguageAbstractionKey: absLang,
		LocalCodeCommitIDKey:   headCtx.remoteCommitID,
		HeadContextKey:         headCtx,
	}

	ctx, err := m.rmSrvtMgr.NOTPPull(headCtx.GetServer(), headCtx.GetServerPAPPort(), headCtx.GetZoneID(), headCtx.GetLedgerID(), bag, m)
	if err != nil {
		return failedOpErr(nil, err)
	}

	localCommitID, _ := getFromRuntimeContext[string](ctx, LocalCodeCommitIDKey)
	output["local_commit_oid"] = localCommitID

	localCommitsCount, _ := getFromRuntimeContext[uint32](ctx, LocalCommitsCountKey)
	output["local_commits_count"] = localCommitsCount

	remoteCommitID, _ := getFromRuntimeContext[string](ctx, RemoteCommitIDKey)
	output["remote_commit_oid"] = remoteCommitID

	remoteCommitCount, _ := getFromRuntimeContext[uint32](ctx, RemoteCommitsCountKey)
	output["remote_commits_count"] = remoteCommitCount

	if localCommitID == remoteCommitID {
		if m.ctx.IsTerminalOutput() {
			out(nil, "", "The local workspace is already fully up to date with the remote ledger.", nil, true)
		}
	} else if localCommitsCount != remoteCommitCount {
		if m.ctx.IsTerminalOutput() {
			out(nil, "", "Not all commits were successfully pulled. Please retry the operation.", nil, true)
		}
		return failedOpErr(nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliRecordExists, "not all commits were successfully pulled."))
	} else {
		committed, _ := getFromRuntimeContext[bool](ctx, CommittedKey)
		if !committed || localCommitID == "" || remoteCommitID == "" {
			if localCommitID != "" && remoteCommitID != "" {
				_, err := m.logsMgr.Log(remoteRefInfo, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, false, remoteRefInfo.GetLedgerURI())
				if err != nil {
					return failedOpErr(nil, err)
				}
			}
		}
		err = m.rfsMgr.SaveRefConfig(remoteRefInfo.GetLedgerID(), remoteRefInfo.GetRef(), remoteCommitID)
		if err != nil {
			_, err = m.logsMgr.Log(remoteRefInfo, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, false, remoteRefInfo.GetLedgerURI())
			if err != nil {
				return failedOpErr(nil, err)
			}
			return failedOpErr(nil, err)
		}
		err = m.rfsMgr.SaveRefWithRemoteConfig(headRefInfo.GetLedgerID(), headRefInfo.GetRef(), remoteRefInfo.GetRef(), remoteCommitID)
		if err != nil {
			_, err = m.logsMgr.Log(headRefInfo, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, false, remoteRefInfo.GetLedgerURI())
			if err != nil {
				return failedOpErr(nil, err)
			}
			return failedOpErr(nil, err)
		}
		_, err = m.logsMgr.Log(remoteRefInfo, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, true, remoteRefInfo.GetLedgerURI())
		if err != nil {
			return failedOpErr(nil, err)
		}
		_, err = m.logsMgr.Log(headRefInfo, localCommitID, remoteCommitID, azicliwkslogs.LogActionPull, true, remoteRefInfo.GetLedgerURI())
		if err != nil {
			return failedOpErr(nil, err)
		}
	}
	if remoteCommitID != azobjs.ZeroOID {
		commitObj, err := m.cospMgr.ReadObject(remoteCommitID)
		if err != nil {
			return failedOpErr(nil, err)
		}
		commit, err := azobjs.ConvertObjectToCommit(commitObj)
		if err != nil {
			return failedOpErr(nil, err)
		}

		treeObj, err := m.cospMgr.ReadObject(commit.GetTree())
		if err != nil {
			return failedOpErr(nil, err)
		}
		tree, err := azobjs.ConvertObjectToTree(treeObj)
		if err != nil {
			return failedOpErr(nil, err)
		}

		codeMap, err := m.cospMgr.ReadCodeSourceCodeMap()
		if err != nil {
			return failedOpErr(nil, err)
		}
		codeMapIds := make(map[string]bool)
		for _, code := range codeMap {
			codeMapIds[code.OID] = true
		}

		var schemaBlock []byte
		codeEntries := []map[string]any{}
		codeBlocks := [][]byte{}
		for _, entry := range tree.GetEntries() {
			codeEntries = append(codeEntries, map[string]any{
				"oid":               entry.GetOID(),
				"oname":             entry.GetOName(),
				"type":              entry.GetType(),
				"code_id":           entry.GetCodeID(),
				"code_type":         entry.GetCodeType(),
				"language":          entry.GetLanguage(),
				"lanaguage_version": entry.GetLanguageVersion(),
				"langauge_type":     entry.GetLanguageType(),
			})
			if _, ok := codeMapIds[entry.GetOID()]; !ok {
				entryObj, err := m.cospMgr.ReadObject(entry.GetOID())
				if err != nil {
					return failedOpErr(nil, err)
				}
				classType, codeBlock, err := azobjs.ReadObjectContentBytes(entryObj)
				if err != nil {
					return failedOpErr(nil, err)
				}
				switch classType {
				case azauthzlangtypes.ClassTypeSchemaID:
					schemaBlock = codeBlock
				case azauthzlangtypes.ClassTypePolicyID:
					objInfo, err := m.objMar.GetObjectInfo(entryObj)
					if err != nil {
						return nil, err
					}
					header := objInfo.GetHeader()
					if header == nil {
						azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientGeneric, "object header is nil")
					}
					langID := header.GetLanguageID()
					langVersionID := header.GetLanguageVersionID()
					langTypeID := header.GetLanguageTypeID()
					// TODO: Fix manifest refactoring
					langCodeBlock, err := absLang.ConvertBytesToFrontendLanguage(nil, "", langID, langVersionID, langTypeID, codeBlock)
					if err != nil {
						return failedOpErr(nil, err)
					}
					codeBlocks = append(codeBlocks, langCodeBlock)
				default:
					return failedOpErr(nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliFileOperation, "invalid class type"))
				}
			}
		}
		output["code_entries"] = codeEntries
		if len(codeBlocks) > 0 {
			// TODO: Fix manifest refactoring
			codeBlock, ext, err := absLang.CreatePolicyContentBytes(nil, "", codeBlocks)
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
			var err error
			// TODO: Fix manifest refactoring
			schemaBlock, _, err = absLang.CreateSchemaContentBytes(nil, "", schemaBlock)
			if err != nil {
				return failedOpErr(nil, err)
			}
			schemaFileNames := absLang.GetSchemaFileNames()
			if len(schemaFileNames) < 1 {
				return failedOpErr(nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliFileOperation, "no schema file names are supported"))
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
		out(nil, "", fmt.Sprintf("Your workspace is synchronized with the remote ledger: %s.", aziclicommon.KeywordText(headCtx.GetLedgerURI())), nil, true)
	}
	return output, nil
}

// ExecPull fetches the latest changes from the remote ledger and constructs the remote state.
func (m *WorkspaceManager) ExecPull(out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to pull changes from the remote ledger.", nil, true)
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

// ExecCloneLedger clones a ledger.
func (m *WorkspaceManager) ExecCloneLedger(ledgerURI string, zapPort, papPort int, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to clone the ledger %s.", aziclicommon.KeywordText(ledgerURI)), nil, true)
		return output, err
	}
	m.ExecPrintContext(nil, out)

	var output map[string]any
	ledgerURI = strings.ToLower(ledgerURI)
	if !strings.HasPrefix(ledgerURI, "permguard@") {
		return failedOpErr(output, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "invalid ledger URI"))
	}
	ledgerURI = strings.TrimPrefix(ledgerURI, "permguard@")
	elements := strings.Split(ledgerURI, "/")
	if len(elements) != 3 {
		return failedOpErr(output, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "invalid ledger URI"))
	}

	uriServer := elements[0]
	uriZoneID := elements[1]
	uriLedger := elements[2]

	output, err := m.ExecInitWorkspace(nil, out)
	aborted := false
	if err == nil {
		fileLock, err := m.tryLock()
		if err != nil {
			return failedOpErr(nil, err)
		}
		defer fileLock.Unlock()
		output, err = m.execInternalAddRemote(true, OriginRemoteName, uriServer, zapPort, papPort, out)
		if err == nil {
			ledgerURI := fmt.Sprintf("%s/%s/%s", OriginRemoteName, uriZoneID, uriLedger)
			output, err = m.execInternalCheckoutLedger(true, ledgerURI, out)
			if err != nil {
				aborted = true
			}
		} else {
			aborted = true
		}
	}
	if aborted {
		return failedOpErr(output, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "operation has been aborted"))
	}
	return output, nil
}
