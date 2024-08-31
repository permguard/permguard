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

package config;

type Config struct {
	Core          CoreConfig `toml:"core"`
	Remotes       map[string]RemoteConfig `toml:"remote"`
	Repositories  map[string]RepositoryConfig `toml:"repository"`
}

type CoreConfig struct {
	ClientVersion string `toml:"client_version"`
}

type RemoteConfig struct {
	URL string `toml:"url"`
	AAP int    `toml:"aap"`
	PAP int    `toml:"pap"`
}

type RepositoryConfig struct {
	Remote string `toml:"remote"`
	Ref    string `toml:"ref"`
}
