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

package validators

import (
	"fmt"
	"strings"
)

// IsValidPath checks if the given path is valid.
func IsValidPath(path string) bool {
	vDirPath := struct {
		Path string `validate:"required,dirpath"`
	}{Path: path}
	isValid, err := ValidateInstance(vDirPath)
	return isValid && err == nil
}

// IsValidPort checks if the given port is valid.
func IsValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

// IsValidHostname checks if the given hostname is valid.
func IsValidHostname(hostnamePath string) bool {
	if hostnamePath == "" {
		return false
	}
	vHostnamePath := struct {
		HostnamePath string `validate:"required,hostname"`
	}{HostnamePath: hostnamePath}
	isValid, err := ValidateInstance(vHostnamePath)
	return isValid && err == nil
}

// IsValidHostnamePort checks if the given hostname port is valid.
func IsValidHostnamePort(hostnamePath string) bool {
	if hostnamePath == "" {
		return false
	}
	vHostnamePath := struct {
		HostnamePath string `validate:"required,hostname_port"`
	}{HostnamePath: hostnamePath}
	isValid, err := ValidateInstance(vHostnamePath)
	return isValid && err == nil
}

// IsValidEndpoint validates that the value is a valid endpoint with scheme (grpc://, grpcs://).
func IsValidEndpoint(value string) bool {
	if value == "" {
		return false
	}
	allowedSchemes := []string{"grpc://", "grpcs://"}
	var hostPort string
	matched := false
	for _, scheme := range allowedSchemes {
		if strings.HasPrefix(value, scheme) {
			hostPort = strings.TrimPrefix(value, scheme)
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	// Reject endpoints with an empty hostname (e.g. grpc://:9091).
	if strings.HasPrefix(hostPort, ":") {
		return false
	}
	return IsValidHostnamePort(hostPort)
}

// ValidateSimpleName validates a simple name.
func ValidateSimpleName(name string) bool {
	vName := struct {
		Name string `validate:"required,simplename"`
	}{Name: name}
	isValid, err := ValidateInstance(vName)
	return isValid && err == nil
}

// ValidateCodeID validates a code id.
// A valid code ID must be a 12-digit number in the range [100000000000, 999999999999].
func ValidateCodeID(codeID int64) bool {
	const (
		minCodeID = int64(100000000000)
		maxCodeID = int64(999999999999)
	)
	return codeID >= minCodeID && codeID <= maxCodeID
}

// formatAsUUID formats a string as a UUID.
func formatAsUUID(s string) string {
	if strings.Contains(s, "-") || strings.Contains(s, " ") || len(s) != 32 {
		return s
	}
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		s[0:8],
		s[8:12],
		s[12:16],
		s[16:20],
		s[20:32],
	)
}

// ValidateUUID validates a UUID.
func ValidateUUID(id string) bool {
	formattedID := formatAsUUID(id)
	vID := struct {
		ID string `validate:"required,uuid4"`
	}{ID: formattedID}
	isValid, err := ValidateInstance(vID)
	return isValid && err == nil
}

// ValidateIdentityUserName validates the identity name specifically for user-type identities.
// It accepts either a valid name or a valid email address.
func ValidateIdentityUserName(name string) bool {
	if ValidateName(name) {
		return true
	}
	vEmail := struct {
		Email string `validate:"required,email"`
	}{Email: name}
	isValid, err := ValidateInstance(vEmail)
	return isValid && err == nil
}

// ValidateName validates a name.
// A valid name must be lowercase, trimmed, and must not start with "permguard".
func ValidateName(name string) bool {
	sanitized := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, "permguard") || name != sanitized {
		return false
	}
	vName := struct {
		Name string `validate:"required,name"`
	}{Name: name}
	isValid, err := ValidateInstance(vName)
	return isValid && err == nil
}

// ValidateWildcardName validates a wildcard name.
// A valid wildcard name must be lowercase, trimmed, and must not start with "permguard".
func ValidateWildcardName(name string) bool {
	sanitized := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, "permguard") || name != sanitized {
		return false
	}
	vName := struct {
		Name string `validate:"required,wildcardname"`
	}{Name: name}
	isValid, err := ValidateInstance(vName)
	return isValid && err == nil
}
