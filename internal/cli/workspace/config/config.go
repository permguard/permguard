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

package config

// config represents the configuration for the workspace.
type config struct {
	Core         coreConfig                  `toml:"core"`
	Remotes      map[string]remoteConfig     `toml:"remote"`
	Repositories map[string]repositoryConfig `toml:"repository"`
}

// coreConfig represents the configuration for the core.
type coreConfig struct {
	ClientVersion string `toml:"client-version"`
	Language      string `toml:"language"`
}

// remoteConfig represents the configuration for the remote.
type remoteConfig struct {
	Server  string `toml:"server"`
	AAPPort int    `toml:"aapport"`
	PAPPort int    `toml:"papport"`
}

// repositoryConfig represents the configuration for the repository.
type repositoryConfig struct {
	Refs   string `toml:"ref"`
	Remote string `toml:"remote"`
}

// RemoteInfo represents the remote information.
type RemoteInfo struct {
	server  string
	aapPort int
	papPort int
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
