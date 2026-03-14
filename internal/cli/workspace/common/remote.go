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
	"errors"
	"fmt"
	"strings"

	"github.com/permguard/permguard/common/pkg/extensions/validators"
)

// RemoteInfo represents the remote information.
type RemoteInfo struct {
	server  string
	zapPort int
	papPort int
	scheme  string
}

// NewRemoteInfo creates a new remote info.
func NewRemoteInfo(server string, zapPort, papPort int, scheme string) (*RemoteInfo, error) {
	if server == "" {
		return nil, errors.New("cli: invalid server: must be a non-empty hostname or IP address")
	}
	if zapPort <= 0 {
		return nil, fmt.Errorf("cli: invalid zap port %d: must be between 1 and 65535", zapPort)
	}
	if papPort <= 0 {
		return nil, fmt.Errorf("cli: invalid pap port %d: must be between 1 and 65535", papPort)
	}
	if scheme != "" && scheme != "grpc" && scheme != "grpcs" {
		return nil, fmt.Errorf("cli: invalid scheme %q: must be 'grpc' (plaintext) or 'grpcs' (TLS)", scheme)
	}
	return &RemoteInfo{
		server:  server,
		zapPort: zapPort,
		papPort: papPort,
		scheme:  scheme,
	}, nil
}

// Server returns the server.
func (i *RemoteInfo) Server() string {
	return i.server
}

// ZAPPort returns the zap port.
func (i *RemoteInfo) ZAPPort() int {
	return i.zapPort
}

// PAPPort returns the pap port.
func (i *RemoteInfo) PAPPort() int {
	return i.papPort
}

// Scheme returns the remote scheme (grpc or grpcs). Empty string means auto-detect.
func (i *RemoteInfo) Scheme() string {
	return i.scheme
}

// SanitizeRemote sanitizes the remote name.
func SanitizeRemote(remote string) (string, error) {
	if len(remote) == 0 {
		return "", errors.New("cli: invalid remote name: remote name cannot be empty")
	}
	remote = strings.ToLower(remote)
	if !validators.ValidateSimpleName(remote) {
		return "", fmt.Errorf("cli: invalid remote name %s: must contain only lowercase letters, numbers, hyphens, and underscores", remote)
	}
	return remote, nil
}
