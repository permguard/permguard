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
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSerializeDeserializeTree tests the CBOR round-trip of Tree objects.
func TestSerializeDeserializeTree(t *testing.T) {
	assert := assert.New(t)
	tree := &Tree{
		entries: []TreeEntry{
			{otype: "blob", oid: "515513cd9200cfe899da7ac17a2293ed23a35674b933010d9736e634d3def5fe", partition: "/", oname: "name1", codeID: "code1", codeTypeID: 2, languageID: 2, languageVersionID: 0, languageTypeID: 2},
			{otype: "blob", oid: "2d8ccd4b8c9331d762c13a0b2824c121baad579f29f9c16d27146ca12d9d6170", partition: "/", oname: "name2", codeID: "code2", codeTypeID: 2, languageID: 2, languageVersionID: 0, languageTypeID: 2},
			{otype: "tree", oid: "fa9b45a58ed64dd7309484a9a4f736930c78b7cb43e23eea22f297e1bf9ff851", partition: "/", oname: "name3", codeID: "code3", codeTypeID: 2, languageID: 2, languageVersionID: 0, languageTypeID: 2},
		},
	}
	objectManager, _ := NewObjectManager()

	// Serialize
	serialized, err := objectManager.SerializeTree(tree)
	assert.NoError(err)
	assert.NotEmpty(serialized)

	// Deserialize
	deserialized, err := objectManager.DeserializeTree(serialized)
	assert.NoError(err)
	assert.NotNil(deserialized)

	// Entries should be sorted by OID after serialization
	assert.Equal(3, len(deserialized.entries), "Entries count mismatch")
	// Verify sorted order (by OID)
	assert.Equal("2d8ccd4b8c9331d762c13a0b2824c121baad579f29f9c16d27146ca12d9d6170", deserialized.entries[0].oid)
	assert.Equal("515513cd9200cfe899da7ac17a2293ed23a35674b933010d9736e634d3def5fe", deserialized.entries[1].oid)
	assert.Equal("fa9b45a58ed64dd7309484a9a4f736930c78b7cb43e23eea22f297e1bf9ff851", deserialized.entries[2].oid)

	// Verify full round-trip of all fields
	for _, entry := range deserialized.entries {
		assert.NotEmpty(entry.otype)
		assert.NotEmpty(entry.partition)
		assert.NotEmpty(entry.oid)
		assert.NotEmpty(entry.oname)
		assert.NotEmpty(entry.codeID)
		assert.NotZero(entry.codeTypeID)
		assert.NotZero(entry.languageID)
		assert.NotZero(entry.languageTypeID)
	}
}

// TestSerializeTreeWithErrors tests the serialization of Tree objects with errors.
func TestSerializeTreeWithErrors(t *testing.T) {
	assert := assert.New(t)
	objectManager, _ := NewObjectManager()
	_, err := objectManager.SerializeTree(nil)
	assert.NotNil(err, "Expected an error for nil tree")
}

// TestDeserializeTreeWithErrors tests the deserialization of Tree objects with errors.
func TestDeserializeTreeWithErrors(t *testing.T) {
	assert := assert.New(t)
	objectManager, _ := NewObjectManager()
	_, err := objectManager.DeserializeTree(nil)
	assert.NotNil(err, "Expected an error for nil data")
}
