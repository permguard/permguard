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

package registry

import (
	"errors"
	"fmt"
	"sync"
)

// PluginMode defines how a language plugin is loaded at runtime.
type PluginMode int

const (
	// PluginModeLocal means the plugin is bundled and runs in-process.
	PluginModeLocal PluginMode = iota
	// PluginModeRemote means the plugin runs as a separate process accessed via gRPC.
	// This mode is currently a predisposition — remote transport is not yet implemented.
	PluginModeRemote
)

// LanguageDescriptor holds static metadata for a registered language plugin.
// It is populated at startup by each language plugin and used by the registry
// to resolve uint32 IDs to human-readable names without calling into the plugin.
type LanguageDescriptor struct {
	// ID is the primary uint32 identifier for this language (e.g. cedar = 1).
	ID uint32
	// Name is the canonical human-readable name for the primary language ID (e.g. "cedar").
	Name string
	// VariantNames maps additional language IDs belonging to this language family
	// to their display names (e.g. cedar-json variant ID 2 → "cedar-json").
	VariantNames map[uint32]string
	// VersionNames maps languageVersionIDs to display strings (e.g. 0 → "0.0").
	VersionNames map[uint32]string
	// TypeNames maps languageTypeIDs to display names (e.g. 1 → "schema", 2 → "policy").
	TypeNames map[uint32]string
	// CodeTypeNames maps codeTypeIDs to display names (e.g. 1 → "schema", 2 → "policy").
	CodeTypeNames map[uint32]string
	// PluginMode indicates whether this plugin runs in-process (Local) or as a
	// remote gRPC subprocess (Remote). Remote mode is a predisposition only.
	PluginMode PluginMode
}

// LanguageRegistry is a concurrency-safe central store of language descriptors.
// Language plugins register their descriptor at startup; the workspace manager
// queries the registry to resolve uint32 IDs to human-readable strings.
type LanguageRegistry struct {
	mu              sync.RWMutex
	byID            map[uint32]*LanguageDescriptor
	variantToLang   map[uint32]uint32 // variantID → primary languageID
	globalTypes     map[uint32]string // union of all TypeNames across languages
	globalCodeTypes map[uint32]string // union of all CodeTypeNames across languages
}

// NewLanguageRegistry creates an empty language registry.
func NewLanguageRegistry() *LanguageRegistry {
	return &LanguageRegistry{
		byID:            make(map[uint32]*LanguageDescriptor),
		variantToLang:   make(map[uint32]uint32),
		globalTypes:     make(map[uint32]string),
		globalCodeTypes: make(map[uint32]string),
	}
}

// Register adds a language descriptor to the registry.
// Returns an error if a descriptor with the same primary ID is already registered.
func (r *LanguageRegistry) Register(desc *LanguageDescriptor) error {
	if desc == nil {
		return errors.New("registry: language descriptor is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[desc.ID]; exists {
		return fmt.Errorf("registry: language id %d is already registered", desc.ID)
	}
	r.byID[desc.ID] = desc
	for varID := range desc.VariantNames {
		r.variantToLang[varID] = desc.ID
	}
	for k, v := range desc.TypeNames {
		r.globalTypes[k] = v
	}
	for k, v := range desc.CodeTypeNames {
		r.globalCodeTypes[k] = v
	}
	return nil
}

// lookup returns the descriptor for a given languageID (primary or variant).
// Must be called with at least r.mu.RLock held.
func (r *LanguageRegistry) lookup(id uint32) *LanguageDescriptor {
	if desc, ok := r.byID[id]; ok {
		return desc
	}
	if primaryID, ok := r.variantToLang[id]; ok {
		return r.byID[primaryID]
	}
	return nil
}

// ResolveLanguageName returns the display name for a language ID or variant ID.
// Falls back to the decimal string representation when the ID is not registered.
func (r *LanguageRegistry) ResolveLanguageName(id uint32) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if desc, ok := r.byID[id]; ok {
		return desc.Name
	}
	if primaryID, ok := r.variantToLang[id]; ok {
		if desc, ok := r.byID[primaryID]; ok {
			if name, ok := desc.VariantNames[id]; ok {
				return name
			}
		}
	}
	return fmt.Sprintf("%d", id)
}

// ResolveVersionName returns the display name for a version ID within the
// context of a given language ID. Falls back to the decimal string when unknown.
func (r *LanguageRegistry) ResolveVersionName(langID, versionID uint32) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	desc := r.lookup(langID)
	if desc == nil {
		return fmt.Sprintf("%d", versionID)
	}
	if name, ok := desc.VersionNames[versionID]; ok {
		return name
	}
	return fmt.Sprintf("%d", versionID)
}

// ResolveTypeName returns the display name for a language type ID.
// The lookup is global across all registered languages.
// Falls back to the decimal string when unknown.
func (r *LanguageRegistry) ResolveTypeName(id uint32) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if name, ok := r.globalTypes[id]; ok {
		return name
	}
	return fmt.Sprintf("%d", id)
}

// ResolveCodeTypeName returns the display name for a code type ID.
// The lookup is global across all registered languages.
// Falls back to the decimal string when unknown.
func (r *LanguageRegistry) ResolveCodeTypeName(id uint32) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if name, ok := r.globalCodeTypes[id]; ok {
		return name
	}
	return fmt.Sprintf("%d", id)
}
