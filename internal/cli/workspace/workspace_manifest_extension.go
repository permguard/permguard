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

package workspace

import (
	"errors"
	"fmt"

	"github.com/permguard/permguard/pkg/authz/languages"
	azmanifests "github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/manifests"
)

type languageInfo struct {
	profileName   string
	partition     string
	lang          *azmanifests.Language
	langAbs       languages.LanguageAbstraction
	schemaEnabled bool
}

// ManifestLanguageProvider manifest language provider.
// The langInfos map is keyed by profile key (profileName + partition, e.g. "ztas_app/", "ztas_app/root1").
type ManifestLanguageProvider struct {
	manifest  *azmanifests.Manifest
	langInfos map[string]languageInfo
}

// ProfileKeys returns all profile keys (profileName + partition).
func (p *ManifestLanguageProvider) ProfileKeys() []string {
	keys := make([]string, 0, len(p.langInfos))
	for k := range p.langInfos {
		keys = append(keys, k)
	}
	return keys
}

// Partition returns the raw partition path for a profile key.
func (p *ManifestLanguageProvider) Partition(profileKey string) (string, error) {
	if p.langInfos == nil {
		return "", fmt.Errorf("cli: profile key %q does not exist", profileKey)
	}
	info, ok := p.langInfos[profileKey]
	if !ok {
		return "", fmt.Errorf("cli: profile key %q does not exist", profileKey)
	}
	return info.partition, nil
}

// Language gets the language for the input profile key.
func (p *ManifestLanguageProvider) Language(profileKey string) (*azmanifests.Language, error) {
	if p.langInfos == nil {
		return nil, fmt.Errorf("cli: profile key %q does not exist", profileKey)
	}
	info, ok := p.langInfos[profileKey]
	if !ok {
		return nil, fmt.Errorf("cli: profile key %q does not exist", profileKey)
	}
	return info.lang, nil
}

// SchemaEnabled returns whether schema is enabled for the given profile key.
func (p *ManifestLanguageProvider) SchemaEnabled(profileKey string) bool {
	if p.langInfos == nil {
		return false
	}
	info, ok := p.langInfos[profileKey]
	if !ok {
		return false
	}
	return info.schemaEnabled
}

// AbstractLanguage gets the abstract language for the input profile key.
func (p *ManifestLanguageProvider) AbstractLanguage(profileKey string) (languages.LanguageAbstraction, error) {
	if p.langInfos == nil {
		return nil, fmt.Errorf("cli: profile key %q does not exist", profileKey)
	}
	info, ok := p.langInfos[profileKey]
	if !ok {
		return nil, fmt.Errorf("cli: profile key %q does not exist", profileKey)
	}
	return info.langAbs, nil
}

// AbstractLanguageByPartition gets the abstract language by partition path (tries all profile keys).
func (p *ManifestLanguageProvider) AbstractLanguageByPartition(partition string) (languages.LanguageAbstraction, error) {
	for _, info := range p.langInfos {
		if info.partition == partition {
			return info.langAbs, nil
		}
	}
	return nil, fmt.Errorf("cli: no profile found for partition %q", partition)
}

// LanguageByPartition gets the language by partition path (tries all profile keys).
func (p *ManifestLanguageProvider) LanguageByPartition(partition string) (*azmanifests.Language, error) {
	for _, info := range p.langInfos {
		if info.partition == partition {
			return info.lang, nil
		}
	}
	return nil, fmt.Errorf("cli: no profile found for partition %q", partition)
}

// buildManifestLanguageManager build a new instance of the manifest language provider.
func (m *Manager) buildManifestLanguageProvider() (*ManifestLanguageProvider, error) {
	manifest, _, err := m.hasValidManifestWorkspaceDir()
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, errors.New("cli: manifest is nil")
	}
	mfestLangMgr := &ManifestLanguageProvider{
		manifest:  manifest,
		langInfos: map[string]languageInfo{},
	}
	for profileName, profile := range manifest.Profiles {
		for partitionKey, partition := range profile.Partitions {
			if _, ok := manifest.Runtimes[partition.Runtime]; !ok {
				continue
			}
			runtime := manifest.Runtimes[partition.Runtime]
			profileKey := profileName + partitionKey
			if _, ok := mfestLangMgr.langInfos[profileKey]; !ok {
				lang := runtime.Language
				absLang, err := m.langFct.LanguageAbstraction(lang.Name, lang.Version)
				if err != nil {
					return nil, err
				}
				mfestLangMgr.langInfos[profileKey] = languageInfo{
					profileName:   profileName,
					partition:     partitionKey,
					lang:          &runtime.Language,
					langAbs:       absLang,
					schemaEnabled: partition.Schema,
				}
			}
		}
	}
	return mfestLangMgr, nil
}
