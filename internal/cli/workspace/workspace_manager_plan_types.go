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

// Remote returns the remote.
func (h *currentHeadContext) Remote() string {
	return h.headRefInfo.Remote()
}

// ZoneID returns the zone id.
func (h *currentHeadContext) ZoneID() int64 {
	return h.headRefInfo.ZoneID()
}

// LedgerID returns the ledger id.
func (h *currentHeadContext) LedgerID() string {
	return h.headRefInfo.LedgerID()
}

// LedgerURI gets the ledger URI.
func (h *currentHeadContext) LedgerURI() string {
	return h.headRefInfo.LedgerURI()
}

// Ref returns the ref.
func (h *currentHeadContext) Ref() string {
	return h.headRefInfo.Ref()
}

// HeadRefInfo returns the head ref information.
func (h *currentHeadContext) HeadRefInfo() *common.RefInfo {
	return h.headRefInfo
}

// GetHeadRef returns the head ref information.
func (h *currentHeadContext) RemoteRefInfo() *common.RefInfo {
	return h.remoteRefInfo
}

// GetRemoteCommitID returns the head commit id.
func (h *currentHeadContext) HeadCommitID() string {
	return h.headCommitID
}

// RemoteCommitID returns the remote commit id.
func (h *currentHeadContext) RemoteCommitID() string {
	return h.remoteCommitID
}

// Server returns the server.
func (h *currentHeadContext) Server() string {
	return h.server
}

// ServerPAPPort returns the server PAP port.
func (h *currentHeadContext) ServerPAPPort() int {
	return h.serverPAPPort
}
