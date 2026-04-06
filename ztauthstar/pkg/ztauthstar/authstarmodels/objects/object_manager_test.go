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

// TestObjectManager tests the functions of ObjectManager.
func TestObjectManager(t *testing.T) {
	objectManager, _ := NewObjectManager()

	t.Run("Test CreateCommitObject and GetObjectInfo", func(t *testing.T) {
		assert := assert.New(t)
		commit := &Commit{
			tree:   CID("bafyrei3b18e17a0e8664d3dffab99ebf6d730ddc6e8649aaaaaaaaaaaaaaaaaa"),
			parent: NullableString{String: "bafyreia1b2c3d4e5f678901234567890abcdef12345678aaaaaaaaaaaaaaaaaaa", Valid: true},
			metaData: CommitMetaData{
				author:             "Nicola Gallo",
				authorTimestamp:    time.Unix(1628704800, 0),
				committer:          "Nicola Gallo",
				committerTimestamp: time.Unix(1628704800, 0),
			},
			message: "Initial commit",
		}

		// Create commit object
		commitObj, err := objectManager.CreateCommitObject(commit)
		assert.NoError(err)
		assert.NotEmpty(commitObj.oid, "OID should not be empty")
		assert.NotEmpty(commitObj.content, "Commit content should not be empty")

		// Get object info
		objectInfo, err := objectManager.ObjectInfo(commitObj)
		assert.NoError(err)
		assert.Equal(ObjectTypeCommit, objectInfo.otype, "Expected commit type")
		assert.NotNil(objectInfo.instance, "Commit instance should not be nil")

		// Cast to commit and validate fields
		retrievedCommit := objectInfo.instance.(*Commit)
		assert.Equal(commit.tree, retrievedCommit.tree, "Tree mismatch")
		assert.Equal(commit.parent, retrievedCommit.parent, "Parents mismatch")
		assert.Equal(commit.metaData.author, retrievedCommit.metaData.author, "Author mismatch")
		assert.Equal(commit.metaData.authorTimestamp.Unix(), retrievedCommit.metaData.authorTimestamp.Unix(), "Author timestamp mismatch")
		assert.Equal(commit.metaData.committer, retrievedCommit.metaData.committer, "Committer mismatch")
		assert.Equal(commit.metaData.committerTimestamp.Unix(), retrievedCommit.metaData.committerTimestamp.Unix(), "Committer timestamp mismatch")
		assert.Equal(commit.message, retrievedCommit.message, "Message mismatch")
	})

	// Test for CreateTreeObject and GetObjectInfo
	t.Run("Test CreateTreeObject and GetObjectInfo", func(t *testing.T) {
		assert := assert.New(t)
		tree := &Tree{
			partition: "/",
			entries: []TreeEntry{
				{otype: "blob", oid: "bafyreiab715b073c6b28e03715129e03a0d52c8e21b73aaaaaaaaaaaaaaaaaaa", oname: "name1", dataType: TreeDataTypePolicy, metadata: map[string]any{MetaKeyCodeID: "code1", MetaKeyCodeTypeID: uint32(2), MetaKeyLanguageID: uint32(2), MetaKeyLanguageVersionID: uint32(1), MetaKeyLanguageTypeID: uint32(2)}},
				{otype: "blob", oid: "bafyreia7fdb22705a5e6145b6a8b1fa947825c5e97a51caaaaaaaaaaaaaaaaaa", oname: "name2", dataType: TreeDataTypePolicy, metadata: map[string]any{MetaKeyCodeID: "code2", MetaKeyCodeTypeID: uint32(2), MetaKeyLanguageID: uint32(2), MetaKeyLanguageVersionID: uint32(1), MetaKeyLanguageTypeID: uint32(2)}},
				{otype: "tree", oid: "bafyreia7fdb33705a5e6145b6a8b1fa947825c5e97a51caaaaaaaaaaaaaaaaaa", oname: "name3", dataType: TreeDataTypePolicy, metadata: map[string]any{MetaKeyCodeID: "code3", MetaKeyCodeTypeID: uint32(2), MetaKeyLanguageID: uint32(2), MetaKeyLanguageVersionID: uint32(1), MetaKeyLanguageTypeID: uint32(2)}},
			},
		}

		// Create tree object
		treeObj, err := objectManager.CreateTreeObject(tree)
		assert.NoError(err)
		assert.NotEmpty(treeObj.oid, "OID should not be empty")
		assert.NotEmpty(treeObj.content, "Tree content should not be empty")

		// Get object info
		objectInfo, err := objectManager.ObjectInfo(treeObj)
		assert.NoError(err)
		assert.Equal(ObjectTypeTree, objectInfo.otype, "Expected tree type")
		assert.NotNil(objectInfo.instance, "Tree instance should not be nil")

		// Cast to tree and validate fields
		retrievedTree := objectInfo.instance.(*Tree)
		assert.Equal(len(tree.entries), len(retrievedTree.entries), "Entries length mismatch")
	})

	// Test for CreateBlobObject and GetObjectInfo
	t.Run("Test CreateBlobObject and GetObjectInfo", func(t *testing.T) {
		assert := assert.New(t)
		blobData := []byte("This is the content of the blob object")

		// Create blob object
		header, _ := NewObjectHeader(DataTypeAbstractTree, map[string]any{
			MetaKeyLanguageID:        uint32(1),
			MetaKeyLanguageVersionID: uint32(1),
			MetaKeyLanguageTypeID:    uint32(1),
			MetaKeyCodeID:            "my-custom-id",
			MetaKeyCodeTypeID:        uint32(1),
		})
		blobObj, err := objectManager.CreateBlobObject(header, blobData)
		assert.NoError(err)
		assert.NotEmpty(blobObj.oid, "OID should not be empty")
		assert.NotEmpty(blobObj.content, "Blob content should not be empty")

		// Get object info
		objectInfo, err := objectManager.ObjectInfo(blobObj)
		assert.NoError(err)
		assert.Equal(ObjectTypeBlob, objectInfo.otype, "Expected blob type")
		assert.NotNil(objectInfo.instance, "Blob instance should not be nil")

		// Validate the content of the blob
		retrievedBlob := objectInfo.instance.([]byte)
		assert.Equal(blobData, retrievedBlob, "Blob content mismatch")

		// Validate header fields
		assert.Equal(DataTypeAbstractTree, objectInfo.header.DataType())
		assert.Equal(uint32(1), objectInfo.header.MetadataUint32(MetaKeyLanguageID))
		assert.Equal(uint32(1), objectInfo.header.MetadataUint32(MetaKeyLanguageVersionID))
		assert.Equal(uint32(1), objectInfo.header.MetadataUint32(MetaKeyLanguageTypeID))
		assert.Equal("my-custom-id", objectInfo.header.MetadataString(MetaKeyCodeID))
		assert.Equal(uint32(1), objectInfo.header.MetadataUint32(MetaKeyCodeTypeID))
	})

	// Test for invalid data
	t.Run("Test invalid object", func(t *testing.T) {
		assert := assert.New(t)
		invalidObj := &Object{content: []byte{}}
		_, err := objectManager.ObjectInfo(invalidObj)
		assert.NotNil(err, "Expected error for empty object content")

		// Test for garbage content
		invalidObj.content = []byte("not valid cbor data at all")
		_, err = objectManager.ObjectInfo(invalidObj)
		assert.NotNil(err, "Expected error for invalid cbor content")
	})
}
