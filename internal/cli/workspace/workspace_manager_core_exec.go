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
	"path/filepath"
	"strings"

	"github.com/permguard/permguard/common/pkg/extensions/ids"
	"github.com/permguard/permguard/common/pkg/extensions/validators"
	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/workspace/persistence"
	"github.com/permguard/permguard/pkg/authz/languages"
	manifests "github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/manifests"
)

// ExecPrintContext prints the context.
func (m *WorkspaceManager) ExecPrintContext(output map[string]any, out common.PrinterOutFunc) map[string]any {
	if !m.ctx.IsVerboseTerminalOutput() {
		return output
	}
	context := m.persMgr.Context()
	for key, value := range context {
		out(nil, "context", fmt.Sprintf("%s '%s'.", key, common.FileText(value)), nil, true)
	}
	return output
}

// InitParms represents the parameters for initializing the workspace.
type InitParms struct {
	// Name of the workspace to be used in the manifest.
	Name string
	// AuthZLanguage the authz language.
	AuthZLanguage string
	// AuthZTemplate the authz template.
	AuthZTemplate string
}

// ExecInitWorkspace initializes the workspace.
func (m *WorkspaceManager) ExecInitWorkspace(initParams *InitParms, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to initialize the workspace.", nil, true)
		return output, err
	}
	m.ExecPrintContext(nil, out)

	homeHiddenDir := m.homeHiddenDir()

	var err error
	var created bool
	created, err = m.persMgr.CreateDirIfNotExists(persistence.WorkDir, homeHiddenDir)
	if err != nil {
		return fail(nil, err)
	}
	firstInit := created

	if initParams != nil {
		name := initParams.Name
		if len(strings.ReplaceAll(name, " ", "")) == 0 {
			name = ids.GenerateID()
		}
		authzLang := strings.ToLower(initParams.AuthZLanguage)
		authzTemplate := strings.ToLower(initParams.AuthZTemplate)

		var requirement *manifests.Requirement
		requirement, err = manifests.ParseRequirement(authzLang)
		if err != nil {
			return fail(nil, err)
		}

		var absLang languages.LanguageAbastraction
		absLang, err = m.langFct.LanguageAbastraction(requirement.Name(), requirement.Version())
		if err != nil {
			return fail(nil, err)
		}

		var manifest *manifests.Manifest
		manifest, err = manifests.NewManifest(name, "")
		if err != nil {
			return fail(nil, err)
		}
		manifest, err = absLang.BuildManifest(manifest, authzTemplate)
		if err != nil {
			return fail(nil, err)
		}

		var manifestData []byte
		manifestData, err = manifests.ConvertManifestToBytes(manifest, true)
		if err != nil {
			return fail(nil, err)
		}

		_, err = m.persMgr.WriteFileIfNotExists(persistence.WorkspaceDir, manifests.ManifestFileName, manifestData, 0o644, false)
		if err != nil {
			return fail(nil, err)
		}
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return fail(nil, err)
	}
	defer fileLock.Unlock()

	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "init", fmt.Sprintf("Initializing Permguard workspace in '%s'.", common.FileText(homeHiddenDir)), nil, true)
	}

	initializers := []func() error{
		m.logsMgr.ExecInitalize,
		m.cfgMgr.ExecInitialize,
		m.rfsMgr.ExecInitalize,
		m.cospMgr.ExecInitalize,
	}
	for _, initializer := range initializers {
		err := initializer()
		if err != nil {
			if m.ctx.IsVerboseTerminalOutput() {
				out(nil, "init", "Initialization failed.", nil, true)
			}
			return fail(nil, err)
		}
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "init", "Initialization succeeded.", nil, true)
	}
	var msg string
	if firstInit {
		msg = fmt.Sprintf("Initialized empty permguard ledger in '%s'.", common.FileText(m.homeDir))
	} else {
		msg = fmt.Sprintf("Reinitialized existing permguard ledger in '%s'.", common.FileText(m.homeDir))
	}
	out(nil, "", msg, nil, true)
	output := map[string]any{}
	absPath := m.homeDir
	if !filepath.IsAbs(absPath) {
		absPath, _ = filepath.Abs(absPath)
	}
	if m.ctx.IsJSONOutput() {
		remoteObj := map[string]any{
			"root": absPath,
		}
		output = out(nil, "workspace", remoteObj, nil, true)
	}
	return output, nil
}

// execInternalAddRemote adds a remote.
func (m *WorkspaceManager) execInternalAddRemote(internal bool, remote string, server string, zapPort int, papPort int, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		if !internal {
			out(nil, "", fmt.Sprintf("Failed to add remote %s.", common.KeywordText(remote)), nil, true)
		}
		return output, err
	}

	if !validators.IsValidHostname(server) {
		return fail(nil, fmt.Errorf("cli: invalid server %s", server))
	}
	if !validators.IsValidPort(zapPort) {
		return fail(nil, fmt.Errorf("cli: invalid zap port %d", zapPort))
	}
	if !validators.IsValidPort(papPort) {
		return fail(nil, fmt.Errorf("cli: invalid pap port %d", papPort))
	}

	output, err := m.cfgMgr.ExecAddRemote(remote, server, zapPort, papPort, nil, out)
	if err != nil {
		return fail(output, err)
	}
	return output, nil
}

// ExecAddRemote adds a remote.
func (m *WorkspaceManager) ExecAddRemote(remote string, server string, zapPort int, papPort int, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to add remote %s.", common.KeywordText(remote)), nil, true)
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

	return m.execInternalAddRemote(false, remote, server, zapPort, papPort, out)
}

// ExecRemoveRemote removes a remote.
func (m *WorkspaceManager) ExecRemoveRemote(remote string, out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", fmt.Sprintf("Failed to remove remote %s.", common.KeywordText(remote)), nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return fail(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return fail(nil, err)
	}
	defer fileLock.Unlock()

	refInfo, err := m.rfsMgr.CurrentHeadRefInfo()
	if err != nil {
		return fail(nil, err)
	}
	if refInfo != nil && refInfo.Remote() == remote {
		if m.ctx.IsVerboseTerminalOutput() {
			out(nil, "remote", "Failed to delete remote: it is associated with the current HEAD.", nil, true)
		}
		return fail(nil, fmt.Errorf("cli: cannot remove the remote used by the currently checked out zone %s", remote))
	}
	output, err = m.cfgMgr.ExecRemoveRemote(remote, output, out)
	return output, err
}

// ExecListRemotes lists the remotes.
func (m *WorkspaceManager) ExecListRemotes(out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to list remotes.", nil, true)
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

	output, err := m.cfgMgr.ExecListRemotes(nil, out)
	return output, err
}

// ExecListLedgers lists the ledgers.
func (m *WorkspaceManager) ExecListLedgers(out common.PrinterOutFunc) (map[string]any, error) {
	fail := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to list ledgers.", nil, true)
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

	output, err := m.cfgMgr.ExecListLedgers(nil, out)
	return output, err
}
