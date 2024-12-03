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

package common

import (
	"fmt"
	"strconv"
	"strings"

	azvalidators "github.com/permguard/permguard/pkg/agents/storage/validators"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// RepoInfo contains the repo information.
type RepoInfo struct {
	remote    string
	accountID int64
	repo      string
}

// GetRemote returns the remote.
func (r *RepoInfo) GetRemote() string {
	return r.remote
}

// GetAccountID returns the account id.
func (r *RepoInfo) GetAccountID() int64 {
	return r.accountID
}

// GetRepo returns the repo.
func (r *RepoInfo) GetRepo() string {
	return r.repo
}

// GetRepoURI gets the repo URI.
func GetRepoURI(remote string, accountID int64, repo string) (string, error) {
	repoInfo := &RepoInfo{
		remote:    remote,
		accountID: accountID,
		repo:      repo,
	}
	return GetRepoURIFromRepoInfo(repoInfo)
}

// GetRepoURIFromRepoInfo gets the repo URI from the repo info.
func GetRepoURIFromRepoInfo(repoInfo *RepoInfo) (string, error) {
	return fmt.Sprintf("%s/%d/%s", repoInfo.remote, repoInfo.accountID, repoInfo.repo), nil
}

// GetRepoInfoFromURI gets the repo information from the URI.
func GetRepoInfoFromURI(repoURI string) (*RepoInfo, error) {
	if len(repoURI) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid repository uri")
	}
	result := &RepoInfo{}
	repoURI = strings.ToLower(repoURI)
	items := strings.Split(repoURI, "/")
	if len(items) < 3 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid repository %s", repoURI))
	}

	remoteName, err := SanitizeRemote(items[0])
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid remote %s", remoteName))
	}
	result.remote = remoteName

	accountIDStr := items[1]
	accountID, err := strconv.ParseInt(accountIDStr, 10, 64)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid account id %s", accountIDStr))
	}
	err = azvalidators.ValidateCodeID("repo", accountID)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid account id %s", accountIDStr))
	}
	result.accountID = accountID

	repoName := items[2]
	err = azvalidators.ValidateName("repo", repoName)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid repository name %s", repoName))
	}
	result.repo = repoName
	return result, nil
}

// SanitizeRepo sanitizes the remote name.
func SanitizeRepo(repoURI string) (string, error) {
	if len(repoURI) == 0 {
		return "", azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid repository uri")
	}
	repoURI = strings.ToLower(repoURI)
	if _, err := GetRepoInfoFromURI(repoURI); err != nil {
		return "", err
	}
	return repoURI, nil
}
