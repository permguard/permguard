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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"

	"github.com/permguard/permguard/internal/cli/common"
	"github.com/permguard/permguard/internal/cli/workspace/config"
	"github.com/permguard/permguard/internal/cli/workspace/cosp"
	"github.com/permguard/permguard/internal/cli/workspace/logs"
	"github.com/permguard/permguard/internal/cli/workspace/persistence"
	refs "github.com/permguard/permguard/internal/cli/workspace/refs"
	"github.com/permguard/permguard/internal/cli/workspace/remoteserver"
	"github.com/permguard/permguard/pkg/authz/languages"
	manifests "github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/manifests"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

const (
	// hiddenDir represents the permguard's hidden directory.
	hiddenDir = ".permguard"
	// hiddenDir represents the permguard's hidden ignore file.
	hiddenIgnoreFile = ".permguardignore"
	// hiddenLockFile represents the permguard's lock file.
	hiddenLockFile = "permguard.lock"
	// gitDir represents the git directory.
	gitDir = ".git"
	// gitIgnoreFile represents the git ignore file.
	gitIgnoreFile = ".gitignore"
)

// WorkspaceManager implements the internal manager to manage the .permguard directory.
type WorkspaceManager struct {
	ctx       *common.CliCommandContext
	homeDir   string
	objMar    *objects.ObjectManager
	langFct   languages.LanguageFactory
	persMgr   *persistence.PersistenceManager
	rmSrvtMgr *remoteserver.RemoteServerManager
	cfgMgr    *config.ConfigManager
	logsMgr   *logs.LogsManager
	rfsMgr    *refs.RefManager
	cospMgr   *cosp.COSPManager
}

// NewInternalManager creates a new internal manager.
func NewInternalManager(ctx *common.CliCommandContext, langFct languages.LanguageFactory) (*WorkspaceManager, error) {
	homeDir := ctx.WorkDir()
	objMar, err := objects.NewObjectManager()
	if err != nil {
		return nil, err
	}
	persMgr, err := persistence.NewPersistenceManager(homeDir, hiddenDir, ctx)
	if err != nil {
		return nil, err
	}
	rmSrvtMgr, err := remoteserver.NewRemoteServerManager(ctx)
	if err != nil {
		return nil, err
	}
	cfgMgr, err := config.NewConfigManager(ctx, persMgr)
	if err != nil {
		return nil, err
	}
	logsMgr, err := logs.NewLogsManager(ctx, persMgr)
	if err != nil {
		return nil, err
	}
	rfsMgr, err := refs.NewRefManager(ctx, persMgr)
	if err != nil {
		return nil, err
	}
	cospMgr, err := cosp.NewPlansManager(ctx, persMgr)
	if err != nil {
		return nil, err
	}
	return &WorkspaceManager{
		homeDir:   homeDir,
		ctx:       ctx,
		objMar:    objMar,
		langFct:   langFct,
		persMgr:   persMgr,
		rmSrvtMgr: rmSrvtMgr,
		cfgMgr:    cfgMgr,
		logsMgr:   logsMgr,
		rfsMgr:    rfsMgr,
		cospMgr:   cospMgr,
	}, nil
}

// homeHiddenDir returns the home hidden directory.
func (m *WorkspaceManager) homeHiddenDir() string {
	return filepath.Join(m.homeDir, hiddenDir)
}

// lockFile returns the lock file.
func (m *WorkspaceManager) lockFile() string {
	return filepath.Join(m.homeHiddenDir(), hiddenLockFile)
}

// isWorkspaceDir checks if the directory is a workspace directory.
func (m *WorkspaceManager) isWorkspaceDir() bool {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	currentDir := m.persMgr.Path(persistence.WorkspaceDir, "")
	currentDir, err = filepath.Abs(currentDir)
	if err != nil {
		return false
	}
	if homeDir == currentDir {
		return false
	}
	isValid, _ := m.persMgr.CheckPathIfExists(persistence.PermguardDir, "")
	return isValid
}

// tryLock tries to lock the workspace.
func (m *WorkspaceManager) tryLock() (*flock.Flock, error) {
	lockFile := m.lockFile()
	m.persMgr.CreateFileIfNotExists(persistence.WorkDir, lockFile)
	fileLock := flock.New(lockFile)
	lock, err := fileLock.TryLock()
	if !lock || err != nil {
		return nil, errors.Join(err, fmt.Errorf("cli: could not acquire the lock, another process is using it %s", m.lockFile()))
	}
	return fileLock, nil
}

// codeFileInfo represents info about the code file.
func (m *WorkspaceManager) printFiles(action string, files []string, out common.PrinterOutFunc) {
	out(nil, "", fmt.Sprintf("	- %s:", action), nil, true)
	for _, file := range files {
		out(nil, "", fmt.Sprintf("	  	- '%s'", common.FileText(common.FileText(file))), nil, true)
	}
}

// raiseWrongWorkspaceDirError raises an error when the directory is not a workspace directory.
func (m *WorkspaceManager) raiseWrongWorkspaceDirError(out common.PrinterOutFunc) error {
	out(nil, "", "The current working directory is not a valid Permguard workspace.", nil, true)
	out(nil, "", "Please initialize the workspace by running the 'init' command.", nil, true)
	return fmt.Errorf("cli: %s is not a permguard workspace directory", m.homeHiddenDir())
}

// hasValidManifestWorkspaceDir checks if the directory is a valid workspace directory.
func (m *WorkspaceManager) hasValidManifestWorkspaceDir() (*manifests.Manifest, error) {
	manifestData, _, err := m.persMgr.ReadFile(persistence.WorkspaceDir, manifests.ManifestFileName, false)
	if err != nil {
		return nil, errors.Join(err, errors.New("cli: could not read the manifest file in the workspace directory"))
	}
	manifest, err := manifests.ConvertBytesToManifest(manifestData)
	manifestErr := errors.New("cli: invalid manifest in the workspace directory")
	if err != nil {
		return nil, errors.Join(err, manifestErr)
	}
	ok, err := manifests.ValidateManifest(manifest)
	if err != nil {
		return nil, errors.Join(err, manifestErr)
	}
	if !ok {
		return nil, errors.Join(err, manifestErr)
	}
	for _, runtime := range manifest.Runtimes {
		lang := runtime.Language
		absLang, err := m.langFct.LanguageAbastraction(lang.Name, lang.Version)
		if err != nil {
			return nil, errors.Join(err, manifestErr)
		}
		ok, err = absLang.ValidateManifest(manifest)
		if err != nil {
			return nil, errors.Join(err, manifestErr)
		}
		if !ok {
			return nil, errors.Join(err, manifestErr)
		}
	}
	return manifest, nil
}
