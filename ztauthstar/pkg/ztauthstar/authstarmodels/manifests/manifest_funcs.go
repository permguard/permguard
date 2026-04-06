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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	// ManifestFileName is the manifest file name.
	ManifestFileName = "manifest.json"
)

// NewManifest creates a new manifest.
func NewManifest(name, description string) (*Manifest, error) {
	manifest := &Manifest{
		Metadata: Metadata{
			Name:        name,
			Description: description,
		},
		Runtimes: make(map[string]Runtime),
		ZtasApp:  []ZtasApp{},
	}
	return manifest, nil
}

var semverRangeRe = regexp.MustCompile(`^(?:\d+\.\d+\.\d+|>=\d+\.\d+\.\d+(?:\s+<\d+\.\d+\.\d+)?)$`)

// ValidateSemverRange validates that the version string is a valid semver range expression.
// Accepted forms: "1.2.3", ">=1.0.0", ">=1.0.0 <2.0.0".
func ValidateSemverRange(version string) bool {
	return semverRangeRe.MatchString(version)
}

// ValidateManifest validates the input manifest.
func ValidateManifest(manifest *Manifest) (bool, error) {
	if manifest == nil {
		return false, errors.New("[ztas] manifest is nil")
	}
	if len(strings.ReplaceAll(manifest.Metadata.Name, " ", "")) == 0 {
		return false, errors.New("[ztas] manifest name is empty")
	}
	for runtimeKey, runtime := range manifest.Runtimes {
		if !ValidateSemverRange(runtime.Language.Version) {
			return false, fmt.Errorf("[ztas] runtime %q has invalid language version: %q", runtimeKey, runtime.Language.Version)
		}
		if !ValidateSemverRange(runtime.Engine.Version) {
			return false, fmt.Errorf("[ztas] runtime %q has invalid engine version: %q", runtimeKey, runtime.Engine.Version)
		}
	}
	if len(manifest.ZtasApp) == 0 {
		return false, errors.New("[ztas] manifest has no ztas_app")
	}
	for i, bizPolicy := range manifest.ZtasApp {
		if _, ok := bizPolicy.Partitions["/"]; !ok {
			return false, fmt.Errorf("[ztas] ztas_app[%d] is missing root partition", i)
		}
		for partKey, partition := range bizPolicy.Partitions {
			if _, ok := manifest.Runtimes[partition.Runtime]; !ok {
				return false, fmt.Errorf("[ztas] ztas_app[%d] partition %q references undefined runtime %q", i, partKey, partition.Runtime)
			}
		}
	}
	return true, nil
}

// ConvertManifestToBytes converts the input  manifest to bytes.
func ConvertManifestToBytes(manifest *Manifest, indent bool) ([]byte, error) {
	if manifest == nil {
		return nil, fmt.Errorf("[ztas] manifest is nil")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(manifest); err != nil {
		return nil, fmt.Errorf("[ztas] failed to serialize the manifest: %w", err)
	}
	data := bytes.TrimRight(buf.Bytes(), "\n")
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
