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

package refs

// HeadConfig represents the configuration for the head.
type HeadConfig struct {
	Head HeadRefsConfig `toml:"refs"`
}

// HeadRefsConfig represents the configuration for the head.
type HeadRefsConfig struct {
	Remote    string `toml:"remote"`
	AccountID int64  `toml:"accountid"`
	Repo      string `toml:"repo"`
	Refs      string `toml:"refs"`
}

// RefsConfig represents the configuration for the refs.
type RefsConfig struct {
	Objects RefsObjectsConfig `toml:"objects"`
}

// RefsObjectsConfig represents the configuration for the objects.
type RefsObjectsConfig struct {
	Commit string `toml:"commit"`
}