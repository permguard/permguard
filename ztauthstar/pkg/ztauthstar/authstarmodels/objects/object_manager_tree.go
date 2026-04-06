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
	OType    string         `cbor:"1,keyasint"`
	OID      string         `cbor:"2,keyasint"`
	OName    string         `cbor:"3,keyasint"`
	DataType uint32         `cbor:"4,keyasint"`
	Metadata map[string]any `cbor:"5,keyasint"`
}

// cborTree is the CBOR-serializable representation of a tree object.
type cborTree struct {
	Entries   []cborTreeEntry `cbor:"1,keyasint"`
	Partition string          `cbor:"2,keyasint"`
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
		entries[i] = cborTreeEntry{
			OType:    entry.otype,
			OID:      entry.oid,
			OName:    entry.oname,
			DataType: entry.dataType,
			Metadata: entry.metadata,
		}
	}
	ct := cborTree{
		Partition: tree.partition,
		Entries:   entries,
	}
	return m.encMode.Marshal(ct)
}

// DeserializeTree deserializes a tree object from CBOR.
func (m *ObjectManager) DeserializeTree(data []byte) (*Tree, error) {
	if data == nil {
		return nil, fmt.Errorf("objects: data is nil")
	}
	var ct cborTree
	if err := m.decMode.Unmarshal(data, &ct); err != nil {
		return nil, fmt.Errorf("objects: failed to decode tree: %w", err)
	}
	tree := &Tree{
		partition: ct.Partition,
		entries:   make([]TreeEntry, len(ct.Entries)),
	}
	for i, e := range ct.Entries {
		tree.entries[i] = TreeEntry{
			otype:    e.OType,
			oid:      e.OID,
			oname:    e.OName,
			dataType: e.DataType,
			metadata: e.Metadata,
		}
	}
	return tree, nil
}
