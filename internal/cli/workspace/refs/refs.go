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

package refs

import (
	"strconv"
	"strings"

	azcrypto "github.com/permguard/permguard-core/pkg/extensions/crypto"
	azicliwksrepos "github.com/permguard/permguard/internal/cli/workspace/repos"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// refsPrefix represents the prefix for the refs.
	refsPrefix = "refs"
	// refsSeparator represents the separator for the refs.
	refsSeparator = "/"
)

// headReferenceConfig represents the configuration for the head.
type headReferenceConfig struct {
	Refs string `toml:"refs"`
}

// headConfig represents the configuration for the head.
type headConfig struct {
	Reference headReferenceConfig `toml:"reference"`
}

// refsObjectsConfig represents the configuration for the objects.
type refsObjectsConfig struct {
	RepoID string `toml:"repoid"`
	Commit string `toml:"commit"`
}

// refsConfig represents the configuration for the refs.
type refsConfig struct {
	Objects refsObjectsConfig `toml:"objects"`
}

// HeadInfo represents the head information.
type HeadInfo struct {
	refs string
}

// GetRefs returns the refs.
func (i *HeadInfo) GetRefs() string {
	return i.refs
}

// GetRefsInfo returns the refs information.
func (i *HeadInfo) GetRefsInfo() (*RefsInfo, error) {
	return convertStringToRefsInfo(i.refs)
}

// computeRefID computes the refid
func computeRefID(remote string, accountID int64, repo string) string {
	repoURI := strings.Join([]string{remote, strconv.FormatInt(accountID, 10), repo}, refsSeparator)
	refID := azcrypto.ComputeStringSHA256(repoURI)
	return refID
}

// generateRefsWithRefID generates the refs with refid.
func generateRefsWithRefID(remote string, accountID int64, repo string, refID string) string {
	return strings.Join([]string{refsPrefix, remote, strconv.FormatInt(accountID, 10), repo, refID}, refsSeparator)
}

// generateRefs generates the refs.
func generateRefs(remote string, accountID int64, repo string) string {
	refID := computeRefID(remote, accountID, repo)
	return generateRefsWithRefID(remote, accountID, repo, refID)
}

// convertStringToRefsInfo converts the string to refs information.
func convertStringToRefsInfo(refs string) (*RefsInfo, error) {
	refsObs := strings.Split(refs, refsSeparator)
	if len(refsObs) != 5 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: malformed refs")
	}
	if refsObs[0] != refsPrefix {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: invalid refs")
	}
	remote := refsObs[1]
	accountID, err := strconv.ParseInt(refsObs[2], 10, 64)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to parse account ID")
	}
	repo := refsObs[3]
	refID := refsObs[4]
	return &RefsInfo{
		remote:    remote,
		accountID: accountID,
		repo:      repo,
		refID:     refID,
	}, nil
}

// convertRefsInfoToString converts the refs information to string.
func convertRefsInfoToString(info *RefsInfo) string {
	return generateRefsWithRefID(info.GetRemote(), info.GetAccountID(), info.GetRepo(), info.GetRefID())
}

// RefsInfo represents the refs information.
type RefsInfo struct {
	remote    string
	accountID int64
	repo      string
	refID     string
}

// GetRemote returns the remote.
func (i *RefsInfo) GetRemote() string {
	return i.remote
}

// GetAccountID returns the account ID.
func (i *RefsInfo) GetAccountID() int64 {
	return i.accountID
}

// GetRepo returns the repo.
func (i *RefsInfo) GetRepo() string {
	return i.repo
}

// GetRefID returns the ref ID.
func (i *RefsInfo) GetRefID() string {
	return i.refID
}

// GetRepoURI returns the repo uri.
func (i *RefsInfo) GetRepoURI() string {
	repoURI, err := azicliwksrepos.GetRepoURI(i.remote, i.accountID, i.repo)
	if err != nil {
		return ""
	}
	return repoURI
}
