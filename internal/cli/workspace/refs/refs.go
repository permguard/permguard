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

package ref

import (
	"strconv"
	"strings"

	azicliwksrepos "github.com/permguard/permguard/internal/cli/workspace/repos"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// refPrefix represents the prefix for the ref.
	refPrefix = "refs"
	// refSeparator represents the separator for the ref.
	refSeparator = "/"
)

// headReferenceConfig represents the configuration for the head.
type headReferenceConfig struct {
	Ref string `toml:"ref"`
}

// headConfig represents the configuration for the head.
type headConfig struct {
	Reference headReferenceConfig `toml:"reference"`
}

// refObjectsConfig represents the configuration for the objects.
type refObjectsConfig struct {
	RepoID string `toml:"repoid"`
	Commit string `toml:"commit"`
}

// refConfig represents the configuration for the ref.
type refConfig struct {
	Objects refObjectsConfig `toml:"objects"`
}

// HeadInfo represents the head information.
type HeadInfo struct {
	ref string
}

// GetRef returns the ref.
func (i *HeadInfo) GetRef() string {
	return i.ref
}

// GetRefInfo returns the ref information.
func (i *HeadInfo) GetRefInfo() (*RefInfo, error) {
	return convertStringToRefInfo(i.ref)
}

// generateRef generates the ref.
func generateRef(remote string, accountID int64, repo string) string {
	return strings.Join([]string{refPrefix, remote, strconv.FormatInt(accountID, 10), repo}, refSeparator)
}

// convertStringToRefInfo converts the string to ref information.
func convertStringToRefInfo(ref string) (*RefInfo, error) {
	refObs := strings.Split(ref, refSeparator)
	if len(refObs) != 5 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: malformed ref")
	}
	if refObs[0] != refPrefix {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: invalid ref")
	}
	remote := refObs[1]
	accountID, err := strconv.ParseInt(refObs[2], 10, 64)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to parse account ID")
	}
	repoID := refObs[3]
	ref = refObs[4]
	return &RefInfo{
		remote:    remote,
		accountID: accountID,
		repoID:    repoID,
		ref:       ref,
	}, nil
}

// convertRefInfoToString converts the ref information to string.
func convertRefInfoToString(info *RefInfo) string {
	return generateRef(info.GetRemote(), info.GetAccountID(), info.GetRepo())
}

// RefInfo represents the ref information.
type RefInfo struct {
	remote    string
	accountID int64
	repoID    string
	ref       string
}

// GetRemote returns the remote.
func (i *RefInfo) GetRemote() string {
	return i.remote
}

// GetAccountID returns the account ID.
func (i *RefInfo) GetAccountID() int64 {
	return i.accountID
}

// GetRepo returns the repo.
func (i *RefInfo) GetRepo() string {
	return i.repoID
}

// GetRef returns the ref ID.
func (i *RefInfo) GetRef() string {
	return i.ref
}

// GetRepoURI returns the repo uri.
func (i *RefInfo) GetRepoURI() string {
	repoURI, err := azicliwksrepos.GetRepoURI(i.remote, i.accountID, i.repoID)
	if err != nil {
		return ""
	}
	return repoURI
}
