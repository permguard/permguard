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

package cedarlang

import (
	"errors"
	"fmt"

	manifests "github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/manifests"
)

const (
	partitionKey = "/"
)

// BuildManifest builds the manifest.
func BuildManifest(manifest *manifests.Manifest, template string, engineName, engineVersion, engineDist string, schema bool) (*manifests.Manifest, error) {
	if manifest == nil {
		return nil, errors.New("[cedar] manifest is nil")
	}
	if len(engineName) == 0 {
		return nil, errors.New("[cedar] engine name is not valid")
	}
	if len(engineVersion) == 0 {
		return nil, errors.New("[cedar] engine version is not valid")
	}
	if len(engineDist) == 0 {
		return nil, errors.New("[cedar] engine distribution is not valid")
	}
	if manifest.Runtimes == nil {
		manifest.Runtimes = map[string]manifests.Runtime{}
	}
	if manifest.Partitions == nil {
		manifest.Partitions = map[string]manifests.Partition{}
	}
	runtimeKey := fmt.Sprintf("%s[%s+]", LanguageCedar, LanguageSyntaxVersion)
	_, ok := manifest.Runtimes[runtimeKey]
	if !ok {
		runtime := manifests.Runtime{
			Engine: manifests.Engine{
				Name:         engineName,
				Version:      engineVersion,
				Distribution: engineDist,
			},
			Language: manifests.Language{
				Name:    LanguageCedar,
				Version: fmt.Sprintf("%s+", LanguageSyntaxVersion),
			},
		}
		manifest.Runtimes[runtimeKey] = runtime
	}
	partition, ok := manifest.Partitions[partitionKey]
	if !ok {
		partition = manifests.Partition{
			Runtime: runtimeKey,
			Schema:  schema,
		}
		manifest.Partitions[partitionKey] = partition
	}
	partition.Runtime = partitionKey
	return manifest, nil
}

// ValidateManifest validates the manifest.
func ValidateManifest(manifest *manifests.Manifest) (bool, error) {
	if manifest == nil {
		return false, errors.New("[cedar] manifest is nil")
	}
	if manifest.Runtimes == nil {
		return false, errors.New("[cedar] manifest has invalid runtimes")
	}
	if manifest.Partitions == nil {
		return false, errors.New("[cedar] manifest has invalid partitions")
	}
	if manifest.Partitions == nil {
		manifest.Partitions = map[string]manifests.Partition{}
	}
	runtimeKey := fmt.Sprintf("%s[%s+]", LanguageCedar, LanguageSyntaxVersion)
	_, ok := manifest.Runtimes[runtimeKey]
	if !ok {
		return false, errors.New("[cedar] manifest is missing cedar runtime")
	}
	partition, ok := manifest.Partitions[partitionKey]
	if !ok {
		return false, errors.New("[cedar] manifest is missing the root partition")
	}
	if partition.Runtime != runtimeKey {
		return false, errors.New("[cedar] manifest has a not valid runtime")
	}
	return true, nil
}
