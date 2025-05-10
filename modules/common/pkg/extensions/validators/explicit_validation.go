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

// IsValidHostname checks if the given hostnameis valid.
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

// ValidateSimpleName validates a simple name.
func ValidateSimpleName(name string) bool {
	vName := struct {
		Name string `validate:"required,simplename"`
	}{Name: name}
	isValid, err := ValidateInstance(vName)
	return isValid && err == nil
}

// ValidateCodeID validates an code id.
func ValidateCodeID(codeID int64) bool {
	vCodeID := struct {
		CodeID int64 `validate:"required,gt=0"`
	}{CodeID: codeID}
	if isValid, err := ValidateInstance(vCodeID); err != nil || !isValid {
		return false
	}
	min := int64(100000000000)
	max := int64(999999999999)
	if codeID < min || codeID > max {
		return false
	}
	return true
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
	if isValid, err := ValidateInstance(vID); err != nil || !isValid {
		return false
	}
	return true
}

// ValidateIdentityUserName validates the identity name specifically for user-type identities.
func ValidateIdentityUserName(name string) bool {
	if ValidateName(name) {
		return true
	}
	vEmail := struct {
		Email string `validate:"required,email"`
	}{Email: name}
	if isValid, err := ValidateInstance(vEmail); err != nil || !isValid {
		return false
	}
	return true
}

// ValidateName validates a name.
func ValidateName(name string) bool {
	sanitized := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, "permguard") {
		return false
	}
	if name != sanitized {
		return false
	}
	vName := struct {
		Name string `validate:"required,name"`
	}{Name: name}
	if isValid, err := ValidateInstance(vName); err != nil || !isValid {
		return false
	}
	return true
}

// ValidateWildcardName validates a wildcard name.
func ValidateWildcardName(name string) bool {
	sanitized := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(name, "permguard") {
		return false
	}
	if name != sanitized {
		return false
	}
	vName := struct {
		Name string `validate:"required,wildcardname"`
	}{Name: name}
	if isValid, err := ValidateInstance(vName); err != nil || !isValid {
		return false
	}
	return true
}
