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
	"github.com/permguard/permguard/internal/cli/workspace/common"
)

// currentHeadContext represents the current head context.
type currentHeadContext struct {
	headRefInfo    *common.RefInfo
	remoteRefInfo  *common.RefInfo
	headCommitID   string
	remoteCommitID string
	server         string
	serverPAPPort  int
}

// GetRemote returns the remote.
func (h *currentHeadContext) GetRemote() string {
	return h.headRefInfo.GetRemote()
}

// GetZoneID returns the zone id.
func (h *currentHeadContext) GetZoneID() int64 {
	return h.headRefInfo.GetZoneID()
}

// GetLedgerID returns the ledger id.
func (h *currentHeadContext) GetLedgerID() string {
	return h.headRefInfo.GetLedgerID()
}

// GetLedgerURI gets the ledger URI.
func (h *currentHeadContext) GetLedgerURI() string {
	return h.headRefInfo.GetLedgerURI()
}

// GetRef returns the ref.
func (h *currentHeadContext) GetRef() string {
	return h.headRefInfo.GetRef()
}

// GetHeadRefInfo returns the head ref information.
func (h *currentHeadContext) GetHeadRefInfo() *common.RefInfo {
	return h.headRefInfo
}

// GetHeadRef returns the head ref information.
func (h *currentHeadContext) GetRemoteRefInfo() *common.RefInfo {
	return h.remoteRefInfo
}

// GetRemoteCommitID returns the head commit id.
func (h *currentHeadContext) GetHeadCommitID() string {
	return h.headCommitID
}

// GetRemoteCommitID returns the remote commit id.
func (h *currentHeadContext) GetRemoteCommitID() string {
	return h.remoteCommitID
}

// GetServer returns the server.
func (h *currentHeadContext) GetServer() string {
	return h.server
}

// GetServerPAPPort returns the server PAP port.
func (h *currentHeadContext) GetServerPAPPort() int {
	return h.serverPAPPort
}
