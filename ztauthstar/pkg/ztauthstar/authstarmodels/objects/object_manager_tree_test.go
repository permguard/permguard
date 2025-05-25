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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSerializeDeserializeTree tests the serialization and deserialization of Tree objects.
func TestSerializeDeserializeTree(t *testing.T) {
	assert := assert.New(t)
	tree := &Tree{
		entries: []TreeEntry{
			{otype: "blob", oid: "515513cd9200cfe899da7ac17a2293ed23a35674b933010d9736e634d3def5fe", partition: "/", oname: "name1", codeID: "code1", codeType: "codeType1", langauge: "cedar", langaugeVersion: "*", langaugeType: "policy"},
			{otype: "blob", oid: "2d8ccd4b8c9331d762c13a0b2824c121baad579f29f9c16d27146ca12d9d6170", partition: "/", oname: "name2", codeID: "code2", codeType: "codeType2", langauge: "cedar", langaugeVersion: "*", langaugeType: "policy"},
			{otype: "tree", oid: "fa9b45a58ed64dd7309484a9a4f736930c78b7cb43e23eea22f297e1bf9ff851", partition: "/", oname: "name3", codeID: "code3", codeType: "codeType3", langauge: "cedar", langaugeVersion: "*", langaugeType: "policy"},
		},
	}
	objectManager, _ := NewObjectManager()
	serialized, err := objectManager.SerializeTree(tree)
	assert.Nil(err)
	expectedSerialized := `blob / 2d8ccd4b8c9331d762c13a0b2824c121baad579f29f9c16d27146ca12d9d6170 name2 code2 codeType2 cedar * policy
blob / 515513cd9200cfe899da7ac17a2293ed23a35674b933010d9736e634d3def5fe name1 code1 codeType1 cedar * policy
tree / fa9b45a58ed64dd7309484a9a4f736930c78b7cb43e23eea22f297e1bf9ff851 name3 code3 codeType3 cedar * policy`
	assert.Equal(expectedSerialized, string(serialized), "Serialized output mismatch")
	expectedLines := strings.Split(expectedSerialized, "\n")
	serializedLines := strings.Split(string(serialized), "\n")
	for i := range expectedLines {
		assert.Equal(expectedLines[i], serializedLines[i], fmt.Sprintf("Mismatch on line %d", i+1))
	}
	assert.Nil(err)
}

// TestSerializeTreeWithErrors tests the serialization of Tree objects with errors.
func TestSerializeTreeWithErrors(t *testing.T) {
	assert := assert.New(t)
	objectManager, _ := NewObjectManager()
	_, err := objectManager.SerializeTree(nil)
	assert.NotNil(err, "Expected an error for invalid data")
}

// TestSerializeDeserializeTreeWithErrors tests the serialization and deserialization of Tree objects with errors.
func TestDeserializeTreeWithErrors(t *testing.T) {
	assert := assert.New(t)
	objectManager, _ := NewObjectManager()
	invalidData := []byte("invalid entry")
	_, err := objectManager.DeserializeTree(invalidData)
	assert.NotNil(err, "Expected an error for invalid data")
}
