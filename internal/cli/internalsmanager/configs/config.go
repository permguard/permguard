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

package configs;

import (
	_ "gopkg.in/ini.v1"
)
type Config struct {
	Core          CoreConfig `ini:"core"`
	Remotes       map[string]RemoteConfig
	Repositories  map[string]RepositoryConfig
}

type CoreConfig struct {
	ClientVersion string `ini:"client_version"`
}

type RemoteConfig struct {
	URL string `ini:"url"`
	AAP int    `ini:"aap"`
	PAP int    `ini:"pap"`
}

type RepositoryConfig struct {
	Remote string `ini:"remote"`
	Ref    string `ini:"ref"`
}
