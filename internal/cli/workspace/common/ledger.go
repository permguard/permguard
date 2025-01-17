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

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azvalidators "github.com/permguard/permguard/pkg/core/validators"
)

// LedgerInfo contains the ledger information.
type LedgerInfo struct {
	remote        string
	applicationID int64
	ledger        string
}

// GetRemote returns the remote.
func (r *LedgerInfo) GetRemote() string {
	return r.remote
}

// GetApplicationID returns the application id.
func (r *LedgerInfo) GetApplicationID() int64 {
	return r.applicationID
}

// GetLedger returns the ledger.
func (r *LedgerInfo) GetLedger() string {
	return r.ledger
}

// GetLedgerURI gets the ledger URI.
func GetLedgerURI(remote string, applicationID int64, ledger string) (string, error) {
	ledgerInfo := &LedgerInfo{
		remote:        remote,
		applicationID: applicationID,
		ledger:        ledger,
	}
	return GetLedgerURIFromLedgerInfo(ledgerInfo)
}

// GetLedgerURIFromLedgerInfo gets the ledger URI from the ledger info.
func GetLedgerURIFromLedgerInfo(ledgerInfo *LedgerInfo) (string, error) {
	return fmt.Sprintf("%s/%d/%s", ledgerInfo.remote, ledgerInfo.applicationID, ledgerInfo.ledger), nil
}

// GetLedgerInfoFromURI gets the ledger information from the URI.
func GetLedgerInfoFromURI(ledgerURI string) (*LedgerInfo, error) {
	if len(ledgerURI) == 0 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "cli: invalid ledger uri")
	}
	result := &LedgerInfo{}
	ledgerURI = strings.ToLower(ledgerURI)
	items := strings.Split(ledgerURI, "/")
	if len(items) < 3 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid ledger %s", ledgerURI))
	}

	remoteName, err := SanitizeRemote(items[0])
	if err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid remote %s", remoteName))
	}
	result.remote = remoteName

	applicationIDStr := items[1]
	applicationID, err := strconv.ParseInt(applicationIDStr, 10, 64)
	if err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid application id %s", applicationIDStr))
	}
	err = azvalidators.ValidateCodeID("ledger", applicationID)
	if err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid application id %s", applicationIDStr))
	}
	result.applicationID = applicationID

	ledgerName := items[2]
	err = azvalidators.ValidateName("ledger", ledgerName)
	if err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid ledger name %s", ledgerName))
	}
	result.ledger = ledgerName
	return result, nil
}

// SanitizeLedger sanitizes the remote name.
func SanitizeLedger(ledgerURI string) (string, error) {
	if len(ledgerURI) == 0 {
		return "", azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliInput, "cli: invalid ledger uri")
	}
	ledgerURI = strings.ToLower(ledgerURI)
	if _, err := GetLedgerInfoFromURI(ledgerURI); err != nil {
		return "", err
	}
	return ledgerURI, nil
}
