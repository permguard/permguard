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
	"strings"

	azmanifests "github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/manifests"
)

const (
	partitionKey       = "/"
	requiredProfileKey = "ztas_app"
)

// BuildManifest builds the manifest.
func BuildManifest(manifest *azmanifests.Manifest, template string, engineName, engineVersion, engineDist string, schema bool) (*azmanifests.Manifest, error) {
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
		manifest.Runtimes = map[string]azmanifests.Runtime{}
	}
	const defaultProfileKey = "ztas_app"
	if len(manifest.Profiles) == 0 {
		manifest.Profiles = map[string]azmanifests.Profile{}
	}
	if _, ok := manifest.Profiles[defaultProfileKey]; !ok {
		manifest.Profiles[defaultProfileKey] = azmanifests.Profile{Partitions: map[string]azmanifests.Partition{}}
	}
	runtimeKey := RuntimeKey
	_, ok := manifest.Runtimes[runtimeKey]
	if !ok {
		runtime := azmanifests.Runtime{
			Engine: azmanifests.Engine{
				Name:         engineName,
				Version:      engineVersion,
				Distribution: engineDist,
			},
			Language: azmanifests.Language{
				Name:    LanguageCedar,
				Version: LanguageManifestVersion,
			},
		}
		manifest.Runtimes[runtimeKey] = runtime
	}
	defaultProfile := manifest.Profiles[defaultProfileKey]
	if _, ok = defaultProfile.Partitions[partitionKey]; !ok {
		defaultProfile.Partitions[partitionKey] = azmanifests.Partition{
			Runtime: runtimeKey,
			Schema:  schema,
		}
		manifest.Profiles[defaultProfileKey] = defaultProfile
	}
	return manifest, nil
}

// ValidateManifest validates the manifest.
func ValidateManifest(manifest *azmanifests.Manifest) (bool, error) {
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
	if _, ok := manifest.Profiles[requiredProfileKey]; !ok {
		return false, fmt.Errorf("[cedar] manifest is missing required profile %q", requiredProfileKey)
	}
	for _, profile := range manifest.Profiles {
		if profile.Partitions == nil {
			continue
		}
		partition, ok := profile.Partitions[partitionKey]
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
