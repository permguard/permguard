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

package pap

// ObjectState represents a transferable object (blob, tree, or commit).
type ObjectState struct {
	OID     string `json:"oid"`
	OType   string `json:"otype"`
	Content []byte `json:"content"`
}

// PushAdvertiseRequest is the request for the push advertise step.
type PushAdvertiseRequest struct {
	ZoneID        int64  `json:"zone_id"`
	LedgerID      string `json:"ledger_id"`
	RefCommit     string `json:"ref_commit"`
	RefPrevCommit string `json:"ref_prev_commit"`
}

// PushAdvertiseResponse is the response for the push advertise step.
type PushAdvertiseResponse struct {
	TxID         string `json:"txid"`
	ServerCommit string `json:"server_commit"`
	HasConflicts bool   `json:"has_conflicts"`
	IsUpToDate   bool   `json:"is_up_to_date"`
}

// PushTransferRequest is the request for the push transfer step.
type PushTransferRequest struct {
	TxID                 string        `json:"txid"`
	ZoneID               int64         `json:"zone_id"`
	LedgerID             string        `json:"ledger_id"`
	Objects              []ObjectState `json:"objects"`
	IsLast               bool          `json:"is_last"`
	RemoteCommitID       string        `json:"remote_commit_id"`
	ExpectedServerCommit string        `json:"expected_server_commit"`
}

// PushTransferResponse is the response for the push transfer step.
type PushTransferResponse struct {
	Committed bool `json:"committed"`
}

// PullStateRequest is the request for the pull state step.
type PullStateRequest struct {
	ZoneID        int64  `json:"zone_id"`
	LedgerID      string `json:"ledger_id"`
	RefCommit     string `json:"ref_commit"`
	RefPrevCommit string `json:"ref_prev_commit"`
}

// PullStateResponse is the response for the pull state step.
type PullStateResponse struct {
	ServerCommit    string `json:"server_commit"`
	NumberOfCommits uint32 `json:"number_of_commits"`
	HasConflicts    bool   `json:"has_conflicts"`
	IsUpToDate      bool   `json:"is_up_to_date"`
}

// PullNegotiateRequest is the request for the pull negotiate step.
type PullNegotiateRequest struct {
	ZoneID         int64  `json:"zone_id"`
	LedgerID       string `json:"ledger_id"`
	LocalCommitID  string `json:"local_commit_id"`
	RemoteCommitID string `json:"remote_commit_id"`
}

// PullNegotiateResponse is the response for the pull negotiate step.
type PullNegotiateResponse struct {
	CommitIDs []string `json:"commit_ids"`
}

// PullObjectsRequest is the request for the pull objects step.
type PullObjectsRequest struct {
	ZoneID   int64  `json:"zone_id"`
	LedgerID string `json:"ledger_id"`
	CommitID string `json:"commit_id"`
}

// PullObjectsResponse is the response for the pull objects step.
type PullObjectsResponse struct {
	Objects []ObjectState `json:"objects"`
}
