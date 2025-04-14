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
	azobjs "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar/authstarmodels/objects"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// CommitInfo define a commit info.
type CommitInfo struct {
	oid    string
	commit *azobjs.Commit
}

// NewCommitInfo creates a new CommitInfo.
func NewCommitInfo(oid string, commit *azobjs.Commit) (*CommitInfo, error) {
	if oid == "" {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "invalid commit oid")
	}
	if commit == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "invalid commit")
	}
	return &CommitInfo{
		oid:    oid,
		commit: commit,
	}, nil
}

// GetOID returns the OID of the commit.
func (c *CommitInfo) GetCommitOID() string {
	return c.oid
}

// GetCommit returns the commit.
func (c *CommitInfo) GetCommit() *azobjs.Commit {
	return c.commit
}
