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
	// refSeparator represents the separator for the ref.
	refSeparator = "/"
	// remotePrefix represents the prefix for the remote.
	remotePrefix = "remotes"
	// headPrefix represents the prefix for the head.
	headPrefix = "heads"
)

// ConvertStringWithRepoIDToRefInfo converts the string with the repo ID to ref information.
func ConvertStringWithRepoIDToRefInfo(ref string) (*RefInfo, error) {
	refObs := strings.Split(ref, refSeparator)
	if len(refObs) != 5 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: malformed ref")
	}
	if refObs[0] != refsPrefix {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid ref")
	}
	sourceType := refObs[1]
	if sourceType != remotePrefix && sourceType != headPrefix {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid source type")
	}
	remote := refObs[2]
	accountID, err := strconv.ParseInt(refObs[3], 10, 64)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: failed to parse account ID")
	}
	repo := refObs[4]
	return &RefInfo{
		sourceType: sourceType,
		remote:     remote,
		accountID:  accountID,
		repoID:     repo,
	}, nil
}

// generateRef generates the ref.
func generateRef(isHead bool, remote string, accountID int64, repo string) string {
	var sourceType string
	if isHead {
		sourceType = headPrefix
	} else {
		sourceType = remotePrefix
	}
	return strings.Join([]string{refsPrefix, sourceType, remote, strconv.FormatInt(accountID, 10), repo}, refSeparator)
}

// GenerateRemoteRef generates the remote ref.
func GenerateRemoteRef(remote string, accountID int64, repo string) string {
	return generateRef(false, remote, accountID, repo)
}

// GenerateRemoteRef generates the remote ref.
func GenerateHeadRef(accountID int64, repo string) string {
	return generateRef(true, HeadKeyword, accountID, repo)
}

// convertRefInfoToString converts the ref information to string.
func ConvertRefInfoToString(refInfo *RefInfo) string {
	return generateRef(refInfo.IsSourceHead(), refInfo.GetRemote(), refInfo.GetAccountID(), refInfo.GetRepo())
}

// RefInfo represents the ref information.
type RefInfo struct {
	sourceType string
	remote     string
	accountID  int64
	repoName   string
	repoID     string
}

// NewRefInfo creates a new ref information.
func NewRefInfoFromRepoName(remote string, accountID int64, repoName string) (*RefInfo, error) {
	if len(remote) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid remote")
	}
	if accountID <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid account ID")
	}
	if len(repoName) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid repository name")
	}
	return &RefInfo{
		sourceType: remotePrefix,
		remote:     remote,
		accountID:  accountID,
		repoName:   repoName,
	}, nil
}

// BuildRefInfoFromRepoID builds the ref information from the repo ID.
func BuildRefInfoFromRepoID(refInfo *RefInfo, repoID string) (*RefInfo, error) {
	if refInfo == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid ref info")
	}
	szRemote, err := SanitizeRemote(refInfo.remote)
	if err != nil {
		return nil, err
	}
	return &RefInfo{
		sourceType: refInfo.sourceType,
		remote:     szRemote,
		accountID:  refInfo.accountID,
		repoName:   refInfo.repoName,
		repoID:     repoID,
	}, nil
}

// GetSourceType returns the source type.
func (i *RefInfo) GetSourceType() string {
	return i.sourceType
}

// IsSourceRemote returns true if the source is remote.
func (i *RefInfo) IsSourceHead() bool {
	return i.sourceType == headPrefix
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

// GetRepo returns the repo.
func (i *RefInfo) GetRepo() string {
	if len(i.repoID) > 0 {
		return i.repoID
	}
	return i.repoName
}

// GetRef returns the ref.
func (i *RefInfo) GetRef() string {
	return generateRef(i.IsSourceHead(), i.GetRemote(), i.GetAccountID(), i.GetRepo())
}

// GetRepoFilePath returns the repo file path.
func (i *RefInfo) GetRepoFilePath(includeFileName bool) string {
	path := filepath.Join(refsPrefix, i.sourceType, i.remote, strconv.FormatInt(i.accountID, 10))
	if includeFileName {
		path = filepath.Join(path, i.GetRepo())
	}
	return path
}

// GetRepoURI returns the repo uri.
func (i *RefInfo) GetRepoURI() string {
	repoURI, err := GetRepoURI(i.remote, i.accountID, i.GetRepo())
	if err != nil {
		return ""
	}
	return repoURI
}
