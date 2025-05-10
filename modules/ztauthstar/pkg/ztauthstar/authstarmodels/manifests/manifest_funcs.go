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

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// ManifestFileName is the manifest file name.
	ManifestFileName = "manifest-authz.json"
)

// NewManifest creates a new manifest.
func NewManifest(kind, name, description string) (*Manifest, error) {
	manifest := &Manifest{
		Metadata: Metadata{
			Kind:        kind,
			Name:        name,
			Description: description,
		},
		Runtimes:   make(map[string]Runtime),
		Partitions: make(map[string]Partition),
	}
	return manifest, nil
}

// ValidateManifest validates the input manifest.
func ValidateManifest(manifest *Manifest) (bool, error) {
	if manifest == nil {
		return false, fmt.Errorf("[ztas] manifest is nil")
	}
	if len(strings.ReplaceAll(manifest.Metadata.Name, " ", "")) == 0 {
		return false, fmt.Errorf("[ztas] manifest name is empty")
	}
	return true, nil
}

// ConvertManifestToBytes converts the input  manifest to bytes.
func ConvertManifestToBytes(manifest *Manifest, indent bool) ([]byte, error) {
	if manifest == nil {
		return nil, fmt.Errorf("[ztas] manifest is nil")
	}
	var data []byte
	var err error
	if indent {
		data, err = json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("[ztas] failed to serialize the manifest: %w", err)
		}
	} else {
		data, err = json.Marshal(manifest)
		if err != nil {
			return nil, fmt.Errorf("[ztas] failed to serialize the manifest: %w", err)
		}
	}
	return data, nil
}

// ConvertBytesToManifest converts the input bytes to a manifest.
func ConvertBytesToManifest(data []byte) (*Manifest, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("[ztas] manifest data is empty")
	}
	manifest := &Manifest{}
	err := json.Unmarshal(data, manifest)
	if err != nil {
		return nil, fmt.Errorf("[ztas] failed to deserialize the manifest: %w", err)
	}
	return manifest, nil
}
