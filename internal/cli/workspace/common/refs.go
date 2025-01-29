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

// ConvertStringWithLedgerIDToRefInfo converts the string with the ledger ID to ref information.
func ConvertStringWithLedgerIDToRefInfo(ref string) (*RefInfo, error) {
	refObs := strings.Split(ref, refSeparator)
	if len(refObs) != 5 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "malformed ref")
	}
	if refObs[0] != refsPrefix {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "invalid ref")
	}
	sourceType := refObs[1]
	if sourceType != remotePrefix && sourceType != headPrefix {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "invalid source type")
	}
	remote := refObs[2]
	zoneID, err := strconv.ParseInt(refObs[3], 10, 64)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrCliInput, "failed to parse zone ID", err)
	}
	ledger := refObs[4]
	return &RefInfo{
		sourceType: sourceType,
		remote:     remote,
		zoneID:     zoneID,
		ledgerID:   ledger,
	}, nil
}

// generateRef generates the ref.
func generateRef(isHead bool, remote string, zoneID int64, ledger string) string {
	var sourceType string
	if isHead {
		sourceType = headPrefix
	} else {
		sourceType = remotePrefix
	}
	return strings.Join([]string{refsPrefix, sourceType, remote, strconv.FormatInt(zoneID, 10), ledger}, refSeparator)
}

// GenerateRemoteRef generates the remote ref.
func GenerateRemoteRef(remote string, zoneID int64, ledger string) string {
	return generateRef(false, remote, zoneID, ledger)
}

// GenerateRemoteRef generates the remote ref.
func GenerateHeadRef(zoneID int64, ledger string) string {
	return generateRef(true, HeadKeyword, zoneID, ledger)
}

// convertRefInfoToString converts the ref information to string.
func ConvertRefInfoToString(refInfo *RefInfo) string {
	return generateRef(refInfo.IsSourceHead(), refInfo.GetRemote(), refInfo.GetZoneID(), refInfo.GetLedger())
}

// RefInfo represents the ref information.
type RefInfo struct {
	sourceType string
	remote     string
	zoneID     int64
	ledgerName string
	ledgerID   string
}

// NewRefInfo creates a new ref information.
func NewRefInfoFromLedgerName(remote string, zoneID int64, ledgerName string) (*RefInfo, error) {
	if len(remote) == 0 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "invalid remote")
	}
	if zoneID <= 0 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "invalid zone ID")
	}
	if len(ledgerName) == 0 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "invalid ledger name")
	}
	return &RefInfo{
		sourceType: remotePrefix,
		remote:     remote,
		zoneID:     zoneID,
		ledgerName: ledgerName,
	}, nil
}

// BuildRefInfoFromLedgerID builds the ref information from the ledger ID.
func BuildRefInfoFromLedgerID(refInfo *RefInfo, ledgerID string) (*RefInfo, error) {
	if refInfo == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "invalid ref info")
	}
	szRemote, err := SanitizeRemote(refInfo.remote)
	if err != nil {
		return nil, err
	}
	return &RefInfo{
		sourceType: refInfo.sourceType,
		remote:     szRemote,
		zoneID:     refInfo.zoneID,
		ledgerName: refInfo.ledgerName,
		ledgerID:   ledgerID,
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

// GetZoneID returns the zone ID.
func (i *RefInfo) GetZoneID() int64 {
	return i.zoneID
}

// GetLedgerName returns the ledger name.
func (i *RefInfo) GetLedgerName() string {
	return i.ledgerName
}

// GetLedgerID returns the ledger id.
func (i *RefInfo) GetLedgerID() string {
	return i.ledgerID
}

// GetLedger returns the ledger.
func (i *RefInfo) GetLedger() string {
	if len(i.ledgerID) > 0 {
		return i.ledgerID
	}
	return i.ledgerName
}

// GetRef returns the ref.
func (i *RefInfo) GetRef() string {
	return generateRef(i.IsSourceHead(), i.GetRemote(), i.GetZoneID(), i.GetLedger())
}

// GetLedgerFilePath returns the ledger file path.
func (i *RefInfo) GetLedgerFilePath(includeFileName bool) string {
	path := filepath.Join(refsPrefix, i.sourceType, i.remote, strconv.FormatInt(i.zoneID, 10))
	if includeFileName {
		path = filepath.Join(path, i.GetLedger())
	}
	return path
}

// GetLedgerURI returns the ledger uri.
func (i *RefInfo) GetLedgerURI() string {
	ledgerURI, err := GetLedgerURI(i.remote, i.zoneID, i.GetLedger())
	if err != nil {
		return ""
	}
	return ledgerURI
}
