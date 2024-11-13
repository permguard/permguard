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
	"path/filepath"
	"strconv"
	"strings"

	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	// refsPrefix represents the prefix for the ref.
	refsPrefix = "refs"
	// remotePrefix represents the prefix for the remote.
	remotePrefix = "remotes"
	// refSeparator represents the separator for the ref.
	refSeparator = "/"
)

// ConvertStringToRefInfo converts the string to ref information.
func ConvertStringToRefInfo(ref string) (*RefInfo, error) {
	refObs := strings.Split(ref, refSeparator)
	if len(refObs) != 4 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: malformed ref")
	}
	if refObs[0] != refsPrefix {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: invalid ref")
	}
	remote := refObs[1]
	accountID, err := strconv.ParseInt(refObs[2], 10, 64)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: failed to parse account ID")
	}
	repoID := refObs[3]
	return &RefInfo{
		remote:    remote,
		accountID: accountID,
		repoID:    repoID,
	}, nil
}

// GenerateRef generates the ref.
func GenerateRef(remote string, accountID int64, repo string) string {
	return strings.Join([]string{refsPrefix, remote, strconv.FormatInt(accountID, 10), repo}, refSeparator)
}

// convertRefInfoToString converts the ref information to string.
func ConvertRefInfoToString(info *RefInfo) string {
	return GenerateRef(info.GetRemote(), info.GetAccountID(), info.GetRepoID())
}

// RefInfo represents the ref information.
type RefInfo struct {
	remote    	string
	accountID	int64
	repoName	string
	repoID		string
}

// NewRefInfo creates a new ref information.
func NewRefInfoFromRepoName(remote string, accountID int64, repoName string) (*RefInfo, error) {
	return &RefInfo{
		remote:    	remote,
		accountID: 	accountID,
		repoName:	repoName,
	}, nil
}

// BuuildRefInfoFromRepoID builds the ref information from the repo ID.
func BuuildRefInfoFromRepoID(refInfo *RefInfo, repoID string) (*RefInfo, error) {
	if refInfo == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliFileOperation, "cli: invalid ref info")
	}
	return &RefInfo{
		remote:    	refInfo.remote,
		accountID: 	refInfo.accountID,
		repoName: 	refInfo.repoName,
		repoID:    	repoID,
	}, nil
}

// GetRemote returns the remote.
func (i *RefInfo) GetRemote() string {
	return i.remote
}

// GetAccountID returns the account ID.
func (i *RefInfo) GetAccountID() int64 {
	return i.accountID
}

// GetRepoName returns the repo name.
func (i *RefInfo) GetRepoName() string {
	return i.repoName
}

// GetRepoID returns the repo id.
func (i *RefInfo) GetRepoID() string {
	return i.repoID
}

// GetRef returns the ref.
func (i *RefInfo) GetRef() string {
	if len(i.repoID) > 0 {
		return GenerateRef(i.remote, i.accountID, i.repoID)
	}
	return GenerateRef(i.remote, i.accountID, i.repoName)
}

// GetRepoFilePath returns the repo file path.
func (i *RefInfo) GetRepoFilePath(includeFileName bool) string {
	path := filepath.Join(remotePrefix, i.remote, strconv.FormatInt(i.accountID, 10), i.repoID)
	if includeFileName {
		path = filepath.Join(path, i.repoID)
	}
	return path
}

// GetRepoURI returns the repo uri.
func (i *RefInfo) GetRepoURI() string {
	repoURI, err := GetRepoURI(i.remote, i.accountID, i.repoID)
	if err != nil {
		return ""
	}
	return repoURI
}
