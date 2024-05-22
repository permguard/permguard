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

package services

import (
	"strings"
)

const (
	HostAllInOne HostKind = "ALL-IN-ONE"
	HostAAP      HostKind = "AAP"
	HostPAP      HostKind = "PAP"
	HostPIP      HostKind = "PIP"
	HostPRP      HostKind = "PRP"
	HostIDP      HostKind = "IDP"
	HostPDP      HostKind = "PDP"
)

// HostKind represents the type of service host.
type HostKind string

// NewHostKindFromString creates a new host kind from a string.
func NewHostKindFromString(host string) (HostKind, error) {
	return HostKind(strings.ToUpper(host)), nil
}

// String returns the string representation of the host.
func (s HostKind) String() string {
	return strings.ToUpper(string(s))
}

// Equal returns true if the host is equal to the input host.
func (s HostKind) Equal(host HostKind) bool {
	return s.String() == host.String()
}

// IsValid returns true if the host is valid.
func (s HostKind) IsValid(hosts []HostKind) bool {
	for _, svc := range hosts {
		if s.Equal(svc) {
			return true
		}
	}
	return false
}

// CanHost returns true if the service can host the desired service.
func (s HostKind) CanHost(service ServiceKind, hosts []HostKind) bool {
	if !s.IsValid(hosts) {
		return false
	}
	if s == HostAllInOne {
		return true
	}
	return s.String() == service.String()
}

// GetServices returns the hostable services.
func (s HostKind) GetServices(hosts []HostKind, services []ServiceKind) []ServiceKind {
	if !s.IsValid(hosts) {
		return []ServiceKind{}
	}
	if s == HostAllInOne {
		svcs := []ServiceKind{}
		for _, svc := range services {
			if s.CanHost(svc, hosts) {
				svcs = append(svcs, svc)
			}
		}
		return svcs
	}
	for _, svc := range services {
		if s.String() == svc.String() {
			return []ServiceKind{svc}
		}
	}
	return []ServiceKind{}
}
