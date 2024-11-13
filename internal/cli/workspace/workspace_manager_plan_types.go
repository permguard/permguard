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

import(
	azicliwkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
)

// currentHeadContext represents the current head context.
type currentHeadContext struct {
	refInfo 		*azicliwkscommon.RefInfo
	commitID      	string
	server        	string
	serverPAPPort 	int
}

// GetRemote returns the remote.
func (h *currentHeadContext) GetRemote() string {
	return h.refInfo.GetRemote()
}

// GetAccountID returns the account id.
func (h *currentHeadContext) GetAccountID() int64 {
	return h.refInfo.GetAccountID()
}

// GetRepoID returns the repo id.
func (h *currentHeadContext) GetRepoID() string {
	return h.refInfo.GetRepoID()
}

// GetRepoURI gets the repo URI.
func (h *currentHeadContext) GetRepoURI() string {
	return h.refInfo.GetRepoURI()
}

// GetRef returns the ref.
func (h *currentHeadContext) GetRef() string {
	return h.refInfo.GetRef()
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
