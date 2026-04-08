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
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// ManifestFileName is the default manifest file name.
	ManifestFileName = "manifest.json"
	// ManifestFormatJSON identifies JSON format.
	ManifestFormatJSON = "json"
	// ManifestFormatYAML identifies YAML format.
	ManifestFormatYAML = "yaml"
)

// ManifestFileNames lists all supported manifest file names.
var ManifestFileNames = []string{"manifest.json", "manifest.yaml", "manifest.yml"}

// NewManifest creates a new manifest.
func NewManifest(name, description string) (*Manifest, error) {
	manifest := &Manifest{
		Metadata: Metadata{
			Name:        name,
			Description: description,
		},
		Runtimes: make(map[string]Runtime),
		Profiles: map[string]Profile{},
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
	if len(manifest.Profiles) == 0 {
		return false, errors.New("[ztas] manifest has no profiles")
	}
	// Validate partitions are unique across all profiles
	seenPartitions := map[string]string{} // partition -> profile that owns it
	for profileKey, profile := range manifest.Profiles {
		if len(profile.Partitions) == 0 {
			return false, fmt.Errorf("[ztas] profile %q has no partitions", profileKey)
		}
		for partKey, partition := range profile.Partitions {
			if partKey != "/" {
				// Partition must be single-level: /name (not /a/b)
				trimmed := strings.TrimPrefix(partKey, "/")
				if trimmed == "" || strings.Contains(trimmed, "/") {
					return false, fmt.Errorf("[ztas] profile %q partition %q is invalid: must be \"/\" or \"/{name}\" (single level only)", profileKey, partKey)
				}
			}
			if _, ok := manifest.Runtimes[partition.Runtime]; !ok {
				return false, fmt.Errorf("[ztas] profile %q partition %q references undefined runtime %q", profileKey, partKey, partition.Runtime)
			}
			if ownerProfile, exists := seenPartitions[partKey]; exists {
				return false, fmt.Errorf("[ztas] partition %q is defined in both profile %q and %q, partitions must be unique across profiles", partKey, ownerProfile, profileKey)
			}
			seenPartitions[partKey] = profileKey
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

// ConvertBytesToManifest converts the input JSON bytes to a manifest.
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

// ConvertManifestToYAMLBytes converts a manifest to YAML bytes.
func ConvertManifestToYAMLBytes(manifest *Manifest) ([]byte, error) {
	if manifest == nil {
		return nil, fmt.Errorf("[ztas] manifest is nil")
	}
	data, err := yaml.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("[ztas] failed to serialize the manifest to YAML: %w", err)
	}
	return bytes.TrimRight(data, "\n"), nil
}

// ConvertYAMLBytesToManifest converts YAML bytes to a manifest.
// It rejects content that is valid JSON, since YAML files must use YAML syntax.
func ConvertYAMLBytesToManifest(data []byte) (*Manifest, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("[ztas] manifest data is empty")
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return nil, fmt.Errorf("[ztas] manifest file has a YAML extension but contains JSON content")
	}
	manifest := &Manifest{}
	err := yaml.Unmarshal(data, manifest)
	if err != nil {
		return nil, fmt.Errorf("[ztas] failed to deserialize the YAML manifest: %w", err)
	}
	return manifest, nil
}

// ConvertBytesToManifestByFormat converts bytes to a manifest using the specified format.
func ConvertBytesToManifestByFormat(data []byte, format string) (*Manifest, error) {
	switch format {
	case ManifestFormatJSON:
		return ConvertBytesToManifest(data)
	case ManifestFormatYAML:
		return ConvertYAMLBytesToManifest(data)
	default:
		return nil, fmt.Errorf("[ztas] unsupported manifest format: %s", format)
	}
}

// ConvertManifestToBytesForFormat converts a manifest to bytes in the specified format.
func ConvertManifestToBytesForFormat(manifest *Manifest, format string) ([]byte, error) {
	switch format {
	case ManifestFormatJSON:
		return ConvertManifestToBytes(manifest, true)
	case ManifestFormatYAML:
		return ConvertManifestToYAMLBytes(manifest)
	default:
		return nil, fmt.Errorf("[ztas] unsupported manifest format: %s", format)
	}
}

// FormatFromFileName returns the format string for a manifest file name.
// Normalizes ".yml" to "yaml".
func FormatFromFileName(filename string) string {
	ext := filepath.Ext(filename)
	switch ext {
	case ".json":
		return ManifestFormatJSON
	case ".yaml", ".yml":
		return ManifestFormatYAML
	default:
		return ""
	}
}

// ManifestFileNameForFormat returns the canonical manifest file name for a format.
func ManifestFileNameForFormat(format string) string {
	switch format {
	case ManifestFormatJSON:
		return "manifest.json"
	case ManifestFormatYAML:
		return "manifest.yaml"
	default:
		return ManifestFileName
	}
}

// DetectManifestFile scans a directory for manifest files and returns the one found.
// Returns an error if zero or more than one manifest file exists.
func DetectManifestFile(dir string) (string, string, error) {
	var found []string
	for _, name := range ManifestFileNames {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		return "", "", errors.New("[ztas] no manifest file found (expected manifest.json, manifest.yaml, or manifest.yml)")
	}
	if len(found) > 1 {
		return "", "", fmt.Errorf("[ztas] multiple manifest files found (%s), only one is allowed", strings.Join(found, ", "))
	}
	filename := found[0]
	format := FormatFromFileName(filename)
	return filename, format, nil
}
