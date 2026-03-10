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
	"strings"

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
	if len(manifest.BizPolicies) == 0 {
		manifest.BizPolicies = []manifests.BizPolicy{{Partitions: map[string]manifests.Partition{}}}
	}
	if manifest.BizPolicies[0].Partitions == nil {
		manifest.BizPolicies[0] = manifests.BizPolicy{Partitions: map[string]manifests.Partition{}}
	}
	runtimeKey := RuntimeKey
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
				Version: LanguageManifestVersion,
			},
		}
		manifest.Runtimes[runtimeKey] = runtime
	}
	if _, ok = manifest.BizPolicies[0].Partitions[partitionKey]; !ok {
		manifest.BizPolicies[0].Partitions[partitionKey] = manifests.Partition{
			Runtime: runtimeKey,
			Schema:  schema,
		}
	}
	return manifest, nil
}

// ValidateManifest validates the manifest.
func ValidateManifest(manifest *manifests.Manifest) (bool, error) {
	if manifest == nil {
		return false, errors.New("[cedar] manifest is nil")
	}
	if strings.TrimSpace(manifest.Metadata.Name) == "" {
		return false, errors.New("[cedar] manifest has invalid name")
	}
	if len(manifest.Runtimes) == 0 {
		return false, errors.New("[cedar] manifest has invalid runtimes")
	}
	cedarRuntimeFound := false
	for _, runtime := range manifest.Runtimes {
		if runtime.Language.Name == LanguageCedar {
			cedarRuntimeFound = true
			break
		}
	}
	if !cedarRuntimeFound {
		return false, errors.New("[cedar] manifest is missing cedar runtime")
	}
	for _, bizPolicy := range manifest.BizPolicies {
		if bizPolicy.Partitions == nil {
			continue
		}
		partition, ok := bizPolicy.Partitions[partitionKey]
		if !ok {
			continue
		}
		runtime, ok := manifest.Runtimes[partition.Runtime]
		if !ok {
			continue
		}
		if runtime.Language.Name != LanguageCedar {
			return false, errors.New("[cedar] manifest root partition does not reference a cedar runtime")
		}
	}
	return true, nil
}
