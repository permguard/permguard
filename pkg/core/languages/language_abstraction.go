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

package languages

import (
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
)

// LanguageAbastraction is the interface for the language abstraction.
type LanguageAbastraction interface {
	// GetLanguageName returns the name of the language.
	GetLanguageName() string
	// GetFileExtensions returns the file extensions.
	GetFileExtensions() []string
	// CreateTreeObject creates a tree object.
	CreateTreeObject(tree *azlangobjs.Tree) (*azlangobjs.Object, error)
	// CreateMultiSectionsObjects create blobs for multi sections objects.
	CreateMultiSectionsObjects(path string, data []byte) (*azlangobjs.MultiSectionsObject, error)
}
