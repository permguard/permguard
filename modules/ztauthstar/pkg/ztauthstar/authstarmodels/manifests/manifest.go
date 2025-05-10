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

package manifest

// Manifest represnts an Auth* model manifest.
type Manifest struct {
	Metadata   Metadata             `json:"metadata"`
	Runtimes   map[string]Runtime   `json:"runtimes"`
	Partitions map[string]Partition `json:"partitions"`
}

// Metadata of the manifest.
type Metadata struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Author      string `json:"author"`
	License     string `json:"license"`
}

// Language of the runtime.
type Language struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Engine of the runtime.
type Engine struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Distribution string `json:"distribution"`
}

// Runtime required for the auth* model.
type Runtime struct {
	Language Language `json:"language"`
	Engine   Engine   `json:"engine"`
}

// Partition of the auth* model.
type Partition struct {
	Runtime string `json:"runtime"`
	Schema  bool   `json:"schema"`
}
