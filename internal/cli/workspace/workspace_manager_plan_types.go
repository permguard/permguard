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

// currentHeadContext represents the current head context.
type currentHeadContext struct {
	remote        string
	accountID     int64
	repo          string
	repoID        string
	repoURI       string
	ref           string
	commitID      string
	server        string
	serverPAPPort int
}

// GetRemote returns the remote.
func (h *currentHeadContext) GetRemote() string {
	return h.remote
}

// GetAccountID returns the account id.
func (h *currentHeadContext) GetAccountID() int64 {
	return h.accountID
}

// GetRepo returns the repo.
func (h *currentHeadContext) GetRepo() string {
	return h.repo
}

// GetRepoID returns the repo id.
func (h *currentHeadContext) GetRepoID() string {
	return h.repoID
}

// GetRepoURI gets the repo URI.
func (h *currentHeadContext) GetRepoURI() string {
	return h.repoURI
}

// GetRef returns the ref.
func (h *currentHeadContext) GetRef() string {
	return h.ref
}

// GetCommit returns the commit.
func (h *currentHeadContext) GetCommit() string {
	return h.commitID
}

// GetServer returns the server.
func (h *currentHeadContext) GetServer() string {
	return h.server
}

// GetServerPAPPort returns the server PAP port.
func (h *currentHeadContext) GetServerPAPPort() int {
	return h.serverPAPPort
}
