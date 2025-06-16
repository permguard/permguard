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

	"github.com/permguard/permguard/pkg/authz/languages"
	manifests "github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/manifests"
)

type languageInfo struct {
	lang    *manifests.Language
	langAbs languages.LanguageAbastraction
}

// ManifestLanguageProvider manifest language provider.
type ManifestLanguageProvider struct {
	manifest  *manifests.Manifest
	langInfos map[string]languageInfo
}

// Partitions gets the partitions for the manifest language provider.
func (p *ManifestLanguageProvider) Partitions() []string {
	partitions := make([]string, 0, len(p.langInfos))
	for partKey := range p.langInfos {
		partitions = append(partitions, partKey)
	}
	return partitions
}

// Language gets the language for the input partition.
func (p *ManifestLanguageProvider) Language(partition string) (*manifests.Language, error) {
	if p.langInfos == nil {
		return nil, errors.New("cli: parition doens't exists")
	}
	langInfo, ok := p.langInfos[partition]
	if !ok {
		return nil, errors.New("cli: parition doens't exists")
	}
	return langInfo.lang, nil
}

// AbstractLanguage gets the abstract language for the input partition.
func (p *ManifestLanguageProvider) AbstractLanguage(partition string) (languages.LanguageAbastraction, error) {
	if p.langInfos == nil {
		return nil, errors.New("cli: parition doens't exists")
	}
	langInfo, ok := p.langInfos[partition]
	if !ok {
		return nil, errors.New("cli: parition doens't exists")
	}
	return langInfo.langAbs, nil
}

// buildManifestLanguageManager build a new instance of the manifest language provider.
func (m *WorkspaceManager) buildManifestLanguageProvider() (*ManifestLanguageProvider, error) {
	manifest, err := m.hasValidManifestWorkspaceDir()
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
	for partitionKey, partition := range manifest.Partitions {
		if _, ok := manifest.Runtimes[partition.Runtime]; !ok {
			continue
		}
		runtime := manifest.Runtimes[partition.Runtime]
		if _, ok := mfestLangMgr.langInfos[partition.Runtime]; !ok {
			lang := runtime.Language
			absLang, err := m.langFct.LanguageAbastraction(lang.Name, lang.Version)
			if err != nil {
				return nil, err
			}
			mfestLangMgr.langInfos[partitionKey] = languageInfo{
				lang:    &runtime.Language,
				langAbs: absLang,
			}
		} else {
			continue
		}
	}
	return mfestLangMgr, nil
}
