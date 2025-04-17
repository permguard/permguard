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

// ManifestLanguageManager manifest language manager.
type ManifestLanguageManager struct {
	manifest *azztasmfests.Manifest
	langAbstractions map[string]azlang.LanguageAbastraction
}

// buildManifestLanguageManager build a new instance of the manifest language manager.
func (m *WorkspaceManager) buildManifestLanguageManager(manifest *azztasmfests.Manifest) (*ManifestLanguageManager, error) {
	if manifest == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrImplementation, "manifest is nil")
	}
	mfestLangMgr := &ManifestLanguageManager{
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
