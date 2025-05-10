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
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSerializeDeserializeCommit tests the serialization and deserialization of Commit objects.
func TestSerializeDeserializeCommit(t *testing.T) {
	assert := assert.New(t)

	// Create an example commit
	commit := &Commit{
		tree:   "4ad3bb52786751f4b6f9839953fe3dcc2278c66648f0d0193f98088b7e4d0c1d",
		parent: "a294ba66f45afd23f8bda3892728601bb509989a80dbb54d7b513dacb8099d76",
		metaData: CommitMetaData{
			author:             "Nicola Gallo",
			authorTimestamp:    time.Unix(1628704800, 0),
			committer:          "Nicola Gallo",
			committerTimestamp: time.Unix(1628704800, 0),
		},
		message: "Initial commit",
	}

	objectManager, _ := NewObjectManager()

	// Serialize the commit
	serialized, err := objectManager.SerializeCommit(commit)
	assert.Nil(err)
	expectedSerialized := `tree 4ad3bb52786751f4b6f9839953fe3dcc2278c66648f0d0193f98088b7e4d0c1d
parent a294ba66f45afd23f8bda3892728601bb509989a80dbb54d7b513dacb8099d76
author 2021-08-11T20:00:00+02:00 Nicola Gallo
committer 2021-08-11T20:00:00+02:00 Nicola Gallo
Initial commit`
	assert.Equal(expectedSerialized, string(serialized), "Serialized output mismatch")

	// Deserialize the commit
	deserializedCommit, err := objectManager.DeserializeCommit(serialized)
	assert.Nil(err)
	assert.NotNil(deserializedCommit)

	// Check if the deserialized commit matches the original commit
	assert.Equal(commit.tree, deserializedCommit.tree, "Tree mismatch")
	assert.Equal(commit.parent, deserializedCommit.parent, "Parents mismatch")
	assert.Equal(commit.metaData.author, deserializedCommit.metaData.author, "Author mismatch")
	assert.Equal(commit.metaData.authorTimestamp.Unix(), deserializedCommit.metaData.authorTimestamp.Unix(), "Author timestamp mismatch")
	assert.Equal(commit.metaData.committer, deserializedCommit.metaData.committer, "Committer mismatch")
	assert.Equal(commit.metaData.committerTimestamp.Unix(), deserializedCommit.metaData.committerTimestamp.Unix(), "Committer timestamp mismatch")
	assert.Equal(commit.message, deserializedCommit.message, "Message mismatch")

	// Test deserialization with nil data
	_, err = objectManager.DeserializeCommit(nil)
	assert.NotNil(err, "Expected error for nil data")
	assert.EqualError(err, "objects: data is nil")

	// Test serialization with nil commit
	_, err = objectManager.SerializeCommit(nil)
	assert.NotNil(err, "Expected error for nil commit")
	assert.EqualError(err, "objects: commit is nil")
}

func TestSerializeDeserializeCommitWithOID(t *testing.T) {
	assert := assert.New(t)

	objectManager, _ := NewObjectManager()

	commit1 := &Commit{
		tree:   "4ad3bb52786751f4b6f9839953fe3dcc2278c66648f0d0193f98088b7e4d0c1d",
		parent: "a294ba66f45afd23f8bda3892728601bb509989a80dbb54d7b513dacb8099d76",
		metaData: CommitMetaData{
			author:             "Nicola Gallo",
			authorTimestamp:    time.Unix(1628704800, 0),
			committer:          "Nicola Gallo",
			committerTimestamp: time.Unix(1628704800, 0),
		},
		message: "Initial commit",
	}
	obj1, _ := objectManager.CreateCommitObject(commit1)
	obj1Info, _ := objectManager.GetObjectInfo(obj1)

	commit2 := obj1Info.instance.(*Commit)
	obj2, _ := objectManager.CreateCommitObject(commit2)

	assert.Equal(obj1.GetOID(), obj2.GetOID(), "OID mismatch")
}
