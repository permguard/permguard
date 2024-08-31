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
