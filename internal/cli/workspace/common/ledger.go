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
	"fmt"
	"strconv"
	"strings"

	cerrors "github.com/permguard/permguard/pkg/core/errors"
	"github.com/permguard/permguard/pkg/core/validators"
)

// LedgerInfo contains the ledger information.
type LedgerInfo struct {
	remote string
	zoneID int64
	ledger string
}

// GetRemote returns the remote.
func (r *LedgerInfo) GetRemote() string {
	return r.remote
}

// GetZoneID returns the zone id.
func (r *LedgerInfo) GetZoneID() int64 {
	return r.zoneID
}

// GetLedger returns the ledger.
func (r *LedgerInfo) GetLedger() string {
	return r.ledger
}

// GetLedgerURI gets the ledger URI.
func GetLedgerURI(remote string, zoneID int64, ledger string) (string, error) {
	ledgerInfo := &LedgerInfo{
		remote: remote,
		zoneID: zoneID,
		ledger: ledger,
	}
	return GetLedgerURIFromLedgerInfo(ledgerInfo)
}

// GetLedgerURIFromLedgerInfo gets the ledger URI from the ledger info.
func GetLedgerURIFromLedgerInfo(ledgerInfo *LedgerInfo) (string, error) {
	return fmt.Sprintf("%s/%d/%s", ledgerInfo.remote, ledgerInfo.zoneID, ledgerInfo.ledger), nil
}

// GetLedgerInfoFromURI gets the ledger information from the URI.
func GetLedgerInfoFromURI(ledgerURI string) (*LedgerInfo, error) {
	if len(ledgerURI) == 0 {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrCliInput, "invalid ledger uri")
	}
	result := &LedgerInfo{}
	ledgerURI = strings.ToLower(ledgerURI)
	items := strings.Split(ledgerURI, "/")
	if len(items) < 3 {
		return nil, cerrors.WrapSystemErrorWithMessage(cerrors.ErrCliInput, fmt.Sprintf("invalid ledger %s", ledgerURI))
	}

	remoteName, err := SanitizeRemote(items[0])
	if err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliInput, fmt.Sprintf("invalid remote %s", remoteName), err)
	}
	result.remote = remoteName

	zoneIDStr := items[1]
	zoneID, err := strconv.ParseInt(zoneIDStr, 10, 64)
	if err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliInput, fmt.Sprintf("invalid zone id %s", zoneIDStr), err)
	}
	err = validators.ValidateCodeID("ledger", zoneID)
	if err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliInput, fmt.Sprintf("invalid zone id %s", zoneIDStr), err)
	}
	result.zoneID = zoneID

	ledgerName := items[2]
	err = validators.ValidateName("ledger", ledgerName)
	if err != nil {
		return nil, cerrors.WrapHandledSysErrorWithMessage(cerrors.ErrCliInput, fmt.Sprintf("invalid ledger name %s", ledgerName), err)
	}
	result.ledger = ledgerName
	return result, nil
}

// SanitizeLedger sanitizes the remote name.
func SanitizeLedger(ledgerURI string) (string, error) {
	if len(ledgerURI) == 0 {
		return "", cerrors.WrapSystemErrorWithMessage(cerrors.ErrCliInput, "invalid ledger uri")
	}
	ledgerURI = strings.ToLower(ledgerURI)
	if _, err := GetLedgerInfoFromURI(ledgerURI); err != nil {
		return "", err
	}
	return ledgerURI, nil
}
