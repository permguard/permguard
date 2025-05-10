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

package cedar

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	azobjs "github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// TestCommitCreation tests the commit creation.
func TestCommitCreation(t *testing.T) {
	assert := assert.New(t)

	langAbs, err := NewCedarLanguageAbstraction()
	assert.Nil(err, "NewCedarLanguageAbstraction should not return an error")
	assert.NotNil(langAbs, "Language abstraction should not be nil")

	tree := "4ad3bb52786751f4b6f9839953fe3dcc2278c66648f0d0193f98088b7e4d0c1d"
	parent := "a294ba66f45afd23f8bda3892728601bb509989a80dbb54d7b513dacb8099d76"
	commit, err := azobjs.NewCommit(tree, parent, "Nicola Gallo", time.Unix(1628704800, 0), "Nicola Gallo", time.Unix(1628704800, 0), "Initial commit")
	assert.Nil(err, "NewCommit should not return an error")
	assert.NotNil(commit, "Commit should not be nil")

	commitObj, err := azobjs.CreateCommitObject(commit)
	assert.Nil(err, "CreateCommitObject should not return an error")
	assert.NotNil(commitObj, "Commit object should not be nil")

	convertedCommit, err := azobjs.ConvertObjectToCommit(commitObj)
	assert.Nil(err, "ConvertObjectToCommit should not return an error")
	assert.NotNil(convertedCommit, "Converted commit should not be nil")
	assert.Equal(commit.GetTree(), convertedCommit.GetTree(), "Tree mismatch")
	assert.Equal(commit.GetParent(), convertedCommit.GetParent(), "Parent mismatch")
	commitMetdata := commit.GetMetaData()
	convertedMetdata := convertedCommit.GetMetaData()
	assert.Equal(commitMetdata.GetAuthor(), convertedMetdata.GetAuthor(), "Author mismatch")
	assert.Equal(commitMetdata.GetAuthorTimestamp().Unix(), convertedMetdata.GetAuthorTimestamp().Unix(), "Author timestamp mismatch")
	assert.Equal(commitMetdata.GetCommitter(), convertedMetdata.GetCommitter(), "Committer mismatch")
	assert.Equal(commitMetdata.GetCommitterTimestamp().Unix(), convertedMetdata.GetCommitterTimestamp().Unix(), "Committer timestamp mismatch")
	assert.Equal(commit.GetMessage(), convertedCommit.GetMessage(), "Message mismatch")
}

// TestTreeCreation tests the commit creation.
func TestTreeCreation(t *testing.T) {
	assert := assert.New(t)

	langAbs, err := NewCedarLanguageAbstraction()
	assert.Nil(err, "NewCedarLanguageAbstraction should not return an error")
	assert.NotNil(langAbs, "Language abstraction should not be nil")

	tree, err := azobjs.NewTree()
	assert.Nil(err, "new tree should not return an error")

	treeItem1, err := azobjs.NewTreeEntry("/", "blob", "515513cd9200cfe899da7ac17a2293ed23a35674b933010d9736e634d3def5fe", "name1", "code1", "codeType1", "cedar", "*", "policy")
	assert.Nil(err, "new tree entry should not return an error")
	tree.AddEntry(treeItem1)

	treeItem2, err := azobjs.NewTreeEntry("/", "blob", "2d8ccd4b8c9331d762c13a0b2824c121baad579f29f9c16d27146ca12d9d6170", "name2", "code2", "codeType2", "cedar", "*", "policy")
	assert.Nil(err, "new tree entry should not return an error")
	tree.AddEntry(treeItem2)

	treeItem3, err := azobjs.NewTreeEntry("/", "tree", "fa9b45a58ed64dd7309484a9a4f736930c78b7cb43e23eea22f297e1bf9ff851", "name3", "code3", "codeType3", "cedar", "*", "policy")
	tree.AddEntry(treeItem3)

	assert.Nil(err, "NewTree should not return an error")

	treeObj, err := azobjs.CreateTreeObject(tree)
	assert.Nil(err, "CreateTreeObject should not return an error")
	assert.NotNil(treeObj, "Tree object should not be nil")

	convertedTree, err := azobjs.ConvertObjectToTree(treeObj)
	assert.Nil(err, "ConvertObjectToTree should not return an error")
	assert.NotNil(convertedTree, "Converted commit should not be nil")

	assert.Equal(len(tree.GetEntries()), len(convertedTree.GetEntries()), "Entries count mismatch")
	for i, entry := range tree.GetEntries() {
		convertedEntry := convertedTree.GetEntries()[i]
		assert.Equal(entry.GetOID(), convertedEntry.GetOID(), "OID mismatch")
		assert.Equal(entry.GetOName(), convertedEntry.GetOName(), "Name mismatch")
		assert.Equal(entry.GetCodeID(), convertedEntry.GetCodeID(), "CodeID mismatch")
		assert.Equal(entry.GetCodeType(), convertedEntry.GetCodeType(), "CodeType mismatch")
		assert.Equal(entry.GetLanguage(), convertedEntry.GetLanguage(), "Language mismatch")
		assert.Equal(entry.GetLanguageType(), convertedEntry.GetLanguageType(), "LanguageType mismatch")
		assert.Equal(entry.GetLanguageVersion(), convertedEntry.GetLanguageVersion(), "LanguageVersion mismatch")
	}
}
