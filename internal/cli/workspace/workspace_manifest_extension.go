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
	azlang "github.com/permguard/permguard/pkg/authz/languages"
	azztasmfests "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar/authstarmodels/manifests"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// ManifestLanguageProvider manifest language provider.
type ManifestLanguageProvider struct {
	manifest *azztasmfests.Manifest
	langAbstractions map[string]azlang.LanguageAbastraction
}

// GetPolicyFileExtensions gets policy file extensions.
func (p *ManifestLanguageProvider) GetPolicyFileExtensions() []string {
	extSet := make(map[string]struct{})
	if p.langAbstractions == nil {
		return nil
	}
	for _, langAbs := range p.langAbstractions {
		for _, ext := range langAbs.GetPolicyFileExtensions() {
			extSet[ext] = struct{}{}
		}
	}
	fileExts := make([]string, 0, len(extSet))
	for ext := range extSet {
		fileExts = append(fileExts, ext)
	}
	return fileExts
}

// GetSchemaFileNames gets schema file names.
func (p *ManifestLanguageProvider) GetSchemaFileNames() []string {
	extSet := make(map[string]struct{})
	if p.langAbstractions == nil {
		return nil
	}
	for _, langAbs := range p.langAbstractions {
		for _, ext := range langAbs.GetSchemaFileNames() {
			extSet[ext] = struct{}{}
		}
	}
	fileExts := make([]string, 0, len(extSet))
	for ext := range extSet {
		fileExts = append(fileExts, ext)
	}
	return fileExts
}

// GetAbastractLanguage gets the abstract language.
func (p *ManifestLanguageProvider) GetAbastractLanguage(partition string) (azlang.LanguageAbastraction, error) {
	if p.langAbstractions == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrConfigurationGeneric, "parition doens't exists")
	}
	absLang, ok := p.langAbstractions[partition]
	if (!ok) {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrConfigurationGeneric, "parition doens't exists")
	}
	return absLang, nil
}

// buildManifestLanguageManager build a new instance of the manifest language provider.
func (m *WorkspaceManager) buildManifestLanguageProvider() (*ManifestLanguageProvider, error) {
	manifest, err := m.hasValidManifestWorkspaceDir()
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrImplementation, "manifest is nil")
	}
	mfestLangMgr := &ManifestLanguageProvider{
		manifest: manifest,
		langAbstractions: map[string]azlang.LanguageAbastraction{},
	}
	for partitionKey, partition := range manifest.Partitions {
		if _, ok := manifest.Runtimes[partition.Runtime]; !ok {
			continue
		}
		runtime := manifest.Runtimes[partition.Runtime]
		if _, ok := mfestLangMgr.langAbstractions[partition.Runtime]; ok {
			absLang, err := m.langFct.GetLanguageAbastraction(runtime.Language.Name)
			if err != nil {
				return nil, err
			}
			mfestLangMgr.langAbstractions[partitionKey] = absLang
		} else {
			continue
		}
	}
	return mfestLangMgr, nil
}
