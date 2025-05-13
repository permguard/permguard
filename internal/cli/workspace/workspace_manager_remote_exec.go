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
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/permguard/permguard/internal/cli/common"
	wkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
	"github.com/permguard/permguard/internal/cli/workspace/logs"
	notpstatemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/authz/languages/types"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"

	"github.com/permguard/permguard/internal/cli/workspace/persistence"
	cerrors "github.com/permguard/permguard/pkg/core/errors"
	"github.com/permguard/permguard/pkg/core/files"
	"github.com/permguard/permguard/pkg/transport/models/pap"
)

const (
	// CodeGenFileName is the name of the codegen file.
	CodeGenFileName = "codegen"
	// OriginRemoteName is the name of the origin remote.
	OriginRemoteName = "origin"
)

// execInternalCheckoutLedger checks out a ledger.
func (m *WorkspaceManager) execInternalCheckoutLedger(internal bool, ledgerURI string, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", fmt.Sprintf("Failed to check out the ledger %s.", common.KeywordText(ledgerURI)), nil, true)
		}
		return output, err
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "checkout", "Initiating remote verification process.", nil, true)
	}

	// Verifies the ledger URI and check if it already exists
	var err error
	var ledgerInfo *wkscommon.LedgerInfo
	ledgerInfo, err = wkscommon.GetLedgerInfoFromURI(ledgerURI)
	if err != nil {
		return fail(nil, err)
	}
	var output map[string]any
	if ok := m.cfgMgr.CheckLedgerIfExists(ledgerURI); !ok {
		// Retrieves the remote information
		var remoteInfo *wkscommon.RemoteInfo
		remoteInfo, err = m.cfgMgr.GetRemoteInfo(ledgerInfo.GetRemote())
		if err != nil {
			return fail(nil, err)
		}
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "checkout", "Retrieving remote ledger information.", nil, true)
		}
		var srvLedger *pap.Ledger
		srvLedger, err = m.rmSrvtMgr.GetServerRemoteLedger(remoteInfo, ledgerInfo)
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "checkout", "Failed to retrieve remote ledger information.", nil, true)
			}
			return fail(nil, err)
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
		if err != nil && !cerrors.AreErrorsEqual(err, cerrors.ErrCliRecordExists) {
			return fail(output, err)
		}
		// Checkout the head
		remoteCommitID := objects.ZeroOID
		var remoteRef, headRef string
		remoteRef, headRef, output, err = m.rfsMgr.ExecCheckoutRefFilesForRemote(ledgerInfo.GetRemote(), ledgerInfo.GetZoneID(), ledgerInfo.GetLedger(), srvLedger.LedgerID, remoteCommitID, output, out)
		if err != nil {
			return fail(nil, err)
		}
		// Read current remote ref info
		var remoteRefInfo *wkscommon.RefInfo
		remoteRefInfo, err = m.rfsMgr.GetRefInfo(remoteRef)
		if err != nil {
			return fail(nil, err)
		}
		_, err = m.logsMgr.Log(remoteRefInfo, remoteCommitID, remoteCommitID, logs.LogActionCheckout, true, remoteRef)
		if err != nil {
			return fail(nil, err)
		}
		// Read current head ref info
		var headRefInfo *wkscommon.RefInfo
		headRefInfo, err = m.rfsMgr.GetRefInfo(headRef)
		if err != nil {
			return fail(nil, err)
		}
		_, err = m.logsMgr.Log(headRefInfo, remoteCommitID, remoteCommitID, logs.LogActionCheckout, true, remoteRef)
		if err != nil {
			return fail(nil, err)
		}
	}

	refInfo, err := m.cfgMgr.GetLedgerInfo(ledgerURI)
	if err != nil {
		return fail(nil, err)
	}
	remoteRef := wkscommon.GenerateHeadRef(refInfo.GetZoneID(), refInfo.GetLedger())
	_, output, err = m.rfsMgr.ExecCheckoutHead(remoteRef, output, out)
	if err != nil {
		return fail(nil, err)
	}

	_, err = m.execInternalPull(true, out)
	if err != nil {
		return fail(nil, err)
	}

	return output, nil
}

// ExecCheckoutLedger checks out a ledger.
func (m *WorkspaceManager) ExecCheckoutLedger(ledgerURI string, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to checkout the ledger %s.", common.KeywordText(ledgerURI)), nil, true)
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

	return m.execInternalCheckoutLedger(false, ledgerURI, out)
}

// execInternalPull executes an internal pull.
func (m *WorkspaceManager) execInternalPull(internal bool, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", "Failed to pull changes from the remote ledger.", nil, true)
		}
		return output, err
	}

	m.execInternalRefresh(true, out)

	output := map[string]any{}

	// Read current head settings
	var err error
	var headCtx *currentHeadContext
	headCtx, err = m.getCurrentHeadContext()
	if err != nil {
		return fail(nil, err)
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
		LocalCodeCommitIDKey: headCtx.remoteCommitID,
		HeadContextKey:       headCtx,
	}

	var ctx *notpstatemachines.StateMachineRuntimeContext
	ctx, err = m.rmSrvtMgr.NOTPPull(headCtx.GetServer(), headCtx.GetServerPAPPort(), headCtx.GetZoneID(), headCtx.GetLedgerID(), bag, m)
	if err != nil {
		return fail(nil, err)
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
		return fail(nil, errors.New("cli: not all commits were successfully pulled"))
	} else {
		committed, _ := getFromRuntimeContext[bool](ctx, CommittedKey)
		if !committed || localCommitID == "" || remoteCommitID == "" {
			if localCommitID != "" && remoteCommitID != "" {
				_, err = m.logsMgr.Log(remoteRefInfo, localCommitID, remoteCommitID, logs.LogActionPull, false, remoteRefInfo.GetLedgerURI())
				if err != nil {
					return fail(nil, err)
				}
			}
		}
		err = m.rfsMgr.SaveRefConfig(remoteRefInfo.GetLedgerID(), remoteRefInfo.GetRef(), remoteCommitID)
		if err != nil {
			_, err = m.logsMgr.Log(remoteRefInfo, localCommitID, remoteCommitID, logs.LogActionPull, false, remoteRefInfo.GetLedgerURI())
			if err != nil {
				return fail(nil, err)
			}
			return fail(nil, err)
		}
		err = m.rfsMgr.SaveRefWithRemoteConfig(headRefInfo.GetLedgerID(), headRefInfo.GetRef(), remoteRefInfo.GetRef(), remoteCommitID)
		if err != nil {
			_, err = m.logsMgr.Log(headRefInfo, localCommitID, remoteCommitID, logs.LogActionPull, false, remoteRefInfo.GetLedgerURI())
			if err != nil {
				return fail(nil, err)
			}
			return fail(nil, err)
		}
		_, err = m.logsMgr.Log(remoteRefInfo, localCommitID, remoteCommitID, logs.LogActionPull, true, remoteRefInfo.GetLedgerURI())
		if err != nil {
			return fail(nil, err)
		}
		_, err = m.logsMgr.Log(headRefInfo, localCommitID, remoteCommitID, logs.LogActionPull, true, remoteRefInfo.GetLedgerURI())
		if err != nil {
			return fail(nil, err)
		}
	}
	if remoteCommitID != objects.ZeroOID {
		langPvd, err := m.buildManifestLanguageProvider()
		if err != nil {
			return fail(nil, err)
		}

		commitObj, err := m.cospMgr.ReadObject(remoteCommitID)
		if err != nil {
			return fail(nil, err)
		}
		commit, err := objects.ConvertObjectToCommit(commitObj)
		if err != nil {
			return fail(nil, err)
		}

		treeObj, err := m.cospMgr.ReadObject(commit.GetTree())
		if err != nil {
			return fail(nil, err)
		}
		tree, err := objects.ConvertObjectToTree(treeObj)
		if err != nil {
			return fail(nil, err)
		}

		codeMap, err := m.cospMgr.ReadCodeSourceCodeMap()
		if err != nil {
			return fail(nil, err)
		}
		codeMapIds := make(map[string]bool)
		for _, code := range codeMap {
			codeMapIds[code.OID] = true
		}

		codeEntries := []map[string]any{}
		schemaBlocks := map[string][]byte{}
		codeBlocks := map[string][][]byte{}
		for _, entry := range tree.GetEntries() {
			codeEntries = append(codeEntries, map[string]any{
				"partition":         entry.GetPartition(),
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
					return fail(nil, err)
				}
				classType, codeBlock, err := objects.ReadObjectContentBytes(entryObj)
				if err != nil {
					return fail(nil, err)
				}
				objInfo, err := m.objMar.GetObjectInfo(entryObj)
				if err != nil {
					return nil, err
				}
				header := objInfo.GetHeader()
				if header == nil {
					return nil, errors.New("cli: object header is nil")
				}
				switch classType {
				case types.ClassTypeSchemaID:
					partition := header.GetPartition()
					if _, ok := schemaBlocks[partition]; !ok {
						schemaBlocks[partition] = []byte{}
					}
					schemaBlocks[partition] = codeBlock
					continue
				case types.ClassTypePolicyID:
					partition := header.GetPartition()
					langID := header.GetLanguageID()
					langVersionID := header.GetLanguageVersionID()
					langTypeID := header.GetLanguageTypeID()
					absLang, err := langPvd.GetAbstractLanguage(partition)
					if err != nil {
						return fail(nil, err)
					}
					langCodeBlock, err := absLang.ConvertBytesToFrontendLanguage(nil, langID, langVersionID, langTypeID, codeBlock)
					if err != nil {
						return fail(nil, err)
					}
					if _, ok := codeBlocks[partition]; !ok {
						codeBlocks[partition] = [][]byte{}
					}
					codeBlocks[partition] = append(codeBlocks[partition], langCodeBlock)
				default:
					return fail(nil, errors.New("cli: invalid class type"))
				}
			}
		}
		output["code_entries"] = codeEntries
		for partition, codeBlockItem := range codeBlocks {
			absLang, err := langPvd.GetAbstractLanguage(partition)
			if err != nil {
				return fail(nil, err)
			}
			codeBlock, ext, err := absLang.CreatePolicyContentBytes(nil, codeBlockItem)
			if err != nil {
				return fail(nil, err)
			}
			fileName, err := files.GenerateUniqueFile(CodeGenFileName, ext)
			if err != nil {
				return fail(nil, err)
			}
			fileBase := strings.TrimPrefix(partition, "/")
			fileName = path.Join(fileBase, fileName)
			m.persMgr.WriteFile(persistence.WorkspaceDir, fileName, codeBlock, 0644, false)
		}
		for partition, schemaBlockItem := range schemaBlocks {
			absLang, err := langPvd.GetAbstractLanguage(partition)
			if err != nil {
				return fail(nil, err)
			}
			schemaBlock, _, err := absLang.CreateSchemaContentBytes(nil, schemaBlockItem)
			if err != nil {
				return fail(nil, err)
			}
			schemaFileNames := absLang.GetSchemaFileNames()
			if len(schemaFileNames) < 1 {
				return fail(nil, errors.New("cli: no schema file names are supported"))
			}
			schemaFileName := schemaFileNames[0]
			fileBase := strings.TrimPrefix(partition, "/")
			schemaFileName = path.Join(fileBase, schemaFileName)
			m.persMgr.WriteFile(persistence.WorkspaceDir, schemaFileName, schemaBlock, 0644, false)
		}
	}

	m.cospMgr.CleanCodeSource()

	if !internal {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, logs.LogActionPull, "The pull has been completed successfully.", nil, true)
		}
		out(nil, "", "Pull process completed successfully.", nil, true)
		out(nil, "", fmt.Sprintf("Your workspace is synchronized with the remote ledger: %s.", common.KeywordText(headCtx.GetLedgerURI())), nil, true)
	}
	return output, nil
}

// ExecPull fetches the latest changes from the remote ledger and constructs the remote state.
func (m *WorkspaceManager) ExecPull(out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to pull changes from the remote ledger.", nil, true)
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

	return m.execInternalPull(false, out)
}

// ExecCloneLedger clones a ledger.
func (m *WorkspaceManager) ExecCloneLedger(ledgerURI string, zapPort, papPort int, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to clone the ledger %s.", common.KeywordText(ledgerURI)), nil, true)
		return output, err
	}
	m.ExecPrintContext(nil, out)

	var output map[string]any
	ledgerURI = strings.ToLower(ledgerURI)
	if !strings.HasPrefix(ledgerURI, "permguard@") {
		return fail(output, errors.New("cli: invalid ledger URI"))
	}
	ledgerURI = strings.TrimPrefix(ledgerURI, "permguard@")
	elements := strings.Split(ledgerURI, "/")
	if len(elements) != 3 {
		return fail(output, errors.New("cli: invalid ledger URI"))
	}

	uriServer := elements[0]
	uriZoneID := elements[1]
	uriLedger := elements[2]

	output, err := m.ExecInitWorkspace(nil, out)
	aborted := false
	if err == nil {
		fileLock, err := m.tryLock()
		if err != nil {
			return fail(nil, err)
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
		return fail(output, errors.New("cli: operation has been aborted"))
	}
	return output, nil
}
