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

// CoreConfig represents the [core] section in the INI file
type CoreConfig struct {
	ClientVersion string `ini:"clientversion"`
}

// RemoteConfig represents a [remote "dev"] or [remote "prod"] section in the INI file
type RemoteConfig struct {
	URL string `ini:"url"`
	AAP int    `ini:"aap"`
	PAP int    `ini:"pap"`
}

// RepositoryConfig represents the [repository "..."] sections in the INI file
type RepositoryConfig struct {
	Remote string `ini:"remote"`
	Ref    string `ini:"ref"`
}

// Config represents the entire configuration structure
type Config struct {
	Core        CoreConfig                   `ini:"core"`
	Remotes     map[string]*RemoteConfig     `ini:"-"`
	Repositories map[string]*RepositoryConfig `ini:"-"`
}
