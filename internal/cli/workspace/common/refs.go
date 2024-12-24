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
	applicationID, err := strconv.ParseInt(refObs[3], 10, 64)
	if err != nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: failed to parse application ID")
	}
	ledger := refObs[4]
	return &RefInfo{
		sourceType:    sourceType,
		remote:        remote,
		applicationID: applicationID,
		ledgerID:      ledger,
	}, nil
}

// generateRef generates the ref.
func generateRef(isHead bool, remote string, applicationID int64, ledger string) string {
	var sourceType string
	if isHead {
		sourceType = headPrefix
	} else {
		sourceType = remotePrefix
	}
	return strings.Join([]string{refsPrefix, sourceType, remote, strconv.FormatInt(applicationID, 10), ledger}, refSeparator)
}

// GenerateRemoteRef generates the remote ref.
func GenerateRemoteRef(remote string, applicationID int64, ledger string) string {
	return generateRef(false, remote, applicationID, ledger)
}

// GenerateRemoteRef generates the remote ref.
func GenerateHeadRef(applicationID int64, ledger string) string {
	return generateRef(true, HeadKeyword, applicationID, ledger)
}

// convertRefInfoToString converts the ref information to string.
func ConvertRefInfoToString(refInfo *RefInfo) string {
	return generateRef(refInfo.IsSourceHead(), refInfo.GetRemote(), refInfo.GetApplicationID(), refInfo.GetLedger())
}

// RefInfo represents the ref information.
type RefInfo struct {
	sourceType    string
	remote        string
	applicationID int64
	ledgerName    string
	ledgerID      string
}

// NewRefInfo creates a new ref information.
func NewRefInfoFromLedgerName(remote string, applicationID int64, ledgerName string) (*RefInfo, error) {
	if len(remote) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid remote")
	}
	if applicationID <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid application ID")
	}
	if len(ledgerName) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid ledger name")
	}
	return &RefInfo{
		sourceType:    remotePrefix,
		remote:        remote,
		applicationID: applicationID,
		ledgerName:    ledgerName,
	}, nil
}

// BuildRefInfoFromLedgerID builds the ref information from the ledger ID.
func BuildRefInfoFromLedgerID(refInfo *RefInfo, ledgerID string) (*RefInfo, error) {
	if refInfo == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid ref info")
	}
	szRemote, err := SanitizeRemote(refInfo.remote)
	if err != nil {
		return nil, err
	}
	return &RefInfo{
		sourceType:    refInfo.sourceType,
		remote:        szRemote,
		applicationID: refInfo.applicationID,
		ledgerName:    refInfo.ledgerName,
		ledgerID:      ledgerID,
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

// GetApplicationID returns the application ID.
func (i *RefInfo) GetApplicationID() int64 {
	return i.applicationID
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
	return generateRef(i.IsSourceHead(), i.GetRemote(), i.GetApplicationID(), i.GetLedger())
}

// GetLedgerFilePath returns the ledger file path.
func (i *RefInfo) GetLedgerFilePath(includeFileName bool) string {
	path := filepath.Join(refsPrefix, i.sourceType, i.remote, strconv.FormatInt(i.applicationID, 10))
	if includeFileName {
		path = filepath.Join(path, i.GetLedger())
	}
	return path
}

// GetLedgerURI returns the ledger uri.
func (i *RefInfo) GetLedgerURI() string {
	ledgerURI, err := GetLedgerURI(i.remote, i.applicationID, i.GetLedger())
	if err != nil {
		return ""
	}
	return ledgerURI
}
