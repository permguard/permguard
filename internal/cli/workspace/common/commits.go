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
	"errors"

	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// CommitInfo define a commit info.
type CommitInfo struct {
	oid    string
	commit *objects.Commit
}

// NewCommitInfo creates a new CommitInfo.
func NewCommitInfo(oid string, commit *objects.Commit) (*CommitInfo, error) {
	if oid == "" {
		return nil, errors.New("cli: invalid commit oid")
	}
	if commit == nil {
		return nil, errors.New("cli: invalid commit")
	}
	return &CommitInfo{
		oid:    oid,
		commit: commit,
	}, nil
}

// CommitOID returns the OID of the commit.
func (c *CommitInfo) CommitOID() string {
	return c.oid
}

// Commit returns the commit.
func (c *CommitInfo) Commit() *objects.Commit {
	return c.commit
}
