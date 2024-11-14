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
	"strings"

	azvalidators "github.com/permguard/permguard-core/pkg/extensions/validators"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// RemoteInfo represents the remote information.
type RemoteInfo struct {
	server  string
	aapPort int
	papPort int
}

// NewRemoteInfo creates a new remote info.
func NewRemoteInfo(server string, aapPort, papPort int) (*RemoteInfo, error) {
	if server == "" {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid server")
	}
	if aapPort <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid aap port")
	}
	if papPort <= 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid pap port")
	}
	return &RemoteInfo{
		server:  server,
		aapPort: aapPort,
		papPort: papPort,
	}, nil
}

// GetServer returns the server.
func (i *RemoteInfo) GetServer() string {
	return i.server
}

// GetAAPPort returns the aap port.
func (i *RemoteInfo) GetAAPPort() int {
	return i.aapPort
}

// GetPAPPort returns the pap port.
func (i *RemoteInfo) GetPAPPort() int {
	return i.papPort
}

// SanitizeRemote sanitizes the remote name.
func SanitizeRemote(remote string) (string, error) {
	if len(remote) == 0 {
		return "", azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid remote name")
	}
	remote = strings.ToLower(remote)
	if !azvalidators.ValidateSimpleName(remote) {
		return "", azerrors.WrapSystemError(azerrors.ErrCliInput, fmt.Sprintf("cli: invalid remote name %s", remote))
	}
	return remote, nil
}
