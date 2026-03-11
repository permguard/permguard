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

package objects

import (
	"fmt"
	"sort"
)

// cborTreeEntry is the CBOR-serializable representation of a tree entry.
type cborTreeEntry struct {
	Type            string `cbor:"1,keyasint"`
	Partition       string `cbor:"2,keyasint"`
	OID             string `cbor:"3,keyasint"`
	OName           string `cbor:"4,keyasint"`
	CodeID          string `cbor:"5,keyasint"`
	CodeType        string `cbor:"6,keyasint"`
	Language        string `cbor:"7,keyasint"`
	LanguageVersion string `cbor:"8,keyasint"`
	LanguageType    string `cbor:"9,keyasint"`
}

// SerializeTree serializes a tree object to CBOR.
func (m *ObjectManager) SerializeTree(tree *Tree) ([]byte, error) {
	if tree == nil {
		return nil, fmt.Errorf("objects: tree is nil")
	}
	sort.Slice(tree.entries, func(i, j int) bool {
		return tree.entries[i].OID() < tree.entries[j].OID()
	})
	entries := make([]cborTreeEntry, len(tree.entries))
	for i, entry := range tree.entries {
		partition := entry.partition
		if partition == "" {
			partition = "/"
		}
		entries[i] = cborTreeEntry{
			Type:            entry.otype,
			Partition:       partition,
			OID:             entry.oid,
			OName:           entry.oname,
			CodeID:          entry.codeID,
			CodeType:        entry.codeType,
			Language:        entry.language,
			LanguageVersion: entry.languageVersion,
			LanguageType:    entry.languageType,
		}
	}
	return m.encMode.Marshal(entries)
}

// DeserializeTree deserializes a tree object from CBOR.
func (m *ObjectManager) DeserializeTree(data []byte) (*Tree, error) {
	if data == nil {
		return nil, fmt.Errorf("objects: data is nil")
	}
	var entries []cborTreeEntry
	if err := m.decMode.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("objects: failed to decode tree: %w", err)
	}
	tree := &Tree{
		entries: make([]TreeEntry, len(entries)),
	}
	for i, e := range entries {
		tree.entries[i] = TreeEntry{
			otype:           e.Type,
			partition:       e.Partition,
			oid:             e.OID,
			oname:           e.OName,
			codeID:          e.CodeID,
			codeType:        e.CodeType,
			language:        e.Language,
			languageVersion: e.LanguageVersion,
			languageType:    e.LanguageType,
		}
	}
	return tree, nil
}
