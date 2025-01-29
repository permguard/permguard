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
	ServiceZAP ServiceKind = "ZAP"
	ServicePAP ServiceKind = "PAP"
	ServicePIP ServiceKind = "PIP"
	ServicePDP ServiceKind = "PDP"
)

// ServiceKind is the type of service.
type ServiceKind string

// NewServiceKindFromString creates a new service kind from a string.
func NewServiceKindFromString(service string) (ServiceKind, error) {
	return ServiceKind(strings.ToUpper(service)), nil
}

// String returns the string representation of the service kind.
func (s ServiceKind) String() string {
	return strings.ToUpper(string(s))
}

// Equal returns true if the service kind is equal to the input service kind.
func (s ServiceKind) Equal(service ServiceKind) bool {
	return s.String() == service.String()
}

// IsValid returns true if the service kind is valid.
func (s ServiceKind) IsValid(services []ServiceKind) bool {
	for _, svc := range services {
		if s.Equal(svc) {
			return true
		}
	}
	return false
}
