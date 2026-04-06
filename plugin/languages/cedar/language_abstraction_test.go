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
	"github.com/stretchr/testify/require"

	cedarlang "github.com/permguard/permguard/ztauthstar-cedar/pkg/cedarlang"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// TestCommitCreation tests the commit creation.
func TestCommitCreation(t *testing.T) {
	assert := assert.New(t)

	langAbs, err := NewCedarLanguageAbstraction()
	require.NoError(t, err, "NewCedarLanguageAbstraction should not return an error")
	assert.NotNil(langAbs, "Language abstraction should not be nil")

	tree := "bafyreib52786751f4b6f9839953fe3dcc2278c66648f0d0193f98088b7e4d0c"
	parent := "bafyreia294ba66f45afd23f8bda3892728601bb509989a80dbb54d7b513dacc"
	commit, err := objects.NewCommit(objects.CID(tree), objects.NewNullableString(&parent), "Nicola Gallo", time.Unix(1628704800, 0), "Nicola Gallo", time.Unix(1628704800, 0), "Initial commit")
	require.NoError(t, err, "NewCommit should not return an error")
	assert.NotNil(commit, "Commit should not be nil")

	commitObj, err := objects.CreateCommitObject(commit)
	require.NoError(t, err, "CreateCommitObject should not return an error")
	assert.NotNil(commitObj, "Commit object should not be nil")

	convertedCommit, err := objects.ConvertObjectToCommit(commitObj)
	require.NoError(t, err, "ConvertObjectToCommit should not return an error")
	assert.NotNil(convertedCommit, "Converted commit should not be nil")
	assert.Equal(commit.Tree(), convertedCommit.Tree(), "Tree mismatch")
	assert.Equal(commit.Parent(), convertedCommit.Parent(), "Parent mismatch")
	commitMetdata := commit.MetaData()
	convertedMetdata := convertedCommit.MetaData()
	assert.Equal(commitMetdata.Author(), convertedMetdata.Author(), "Author mismatch")
	assert.Equal(commitMetdata.AuthorTimestamp().Unix(), convertedMetdata.AuthorTimestamp().Unix(), "Author timestamp mismatch")
	assert.Equal(commitMetdata.Committer(), convertedMetdata.Committer(), "Committer mismatch")
	assert.Equal(commitMetdata.CommitterTimestamp().Unix(), convertedMetdata.CommitterTimestamp().Unix(), "Committer timestamp mismatch")
	assert.Equal(commit.Message(), convertedCommit.Message(), "Message mismatch")
}

// TestTreeCreation tests the commit creation.
func TestTreeCreation(t *testing.T) {
	assert := assert.New(t)

	langAbs, err := NewCedarLanguageAbstraction()
	require.NoError(t, err, "NewCedarLanguageAbstraction should not return an error")
	assert.NotNil(langAbs, "Language abstraction should not be nil")

	tree, err := objects.NewTree("/")
	require.NoError(t, err, "new tree should not return an error")

	meta1 := map[string]any{
		objects.MetaKeyCodeID: "code1", objects.MetaKeyCodeTypeID: cedarlang.LanguagePolicyTypeID,
		objects.MetaKeyLanguageID: cedarlang.LanguageCedarJSONID, objects.MetaKeyLanguageVersionID: cedarlang.LanguageSyntaxVersionID, objects.MetaKeyLanguageTypeID: cedarlang.LanguagePolicyTypeID,
	}
	treeItem1, err := objects.NewTreeEntry("blob", "bafyreia515513cd9200cfe899da7ac17a2293ed23a35674b933010d9736e634", "name1", objects.TreeDataTypePolicy, meta1)
	require.NoError(t, err, "new tree entry should not return an error")
	_ = tree.AddEntry(treeItem1)

	meta2 := map[string]any{
		objects.MetaKeyCodeID: "code2", objects.MetaKeyCodeTypeID: cedarlang.LanguagePolicyTypeID,
		objects.MetaKeyLanguageID: cedarlang.LanguageCedarJSONID, objects.MetaKeyLanguageVersionID: cedarlang.LanguageSyntaxVersionID, objects.MetaKeyLanguageTypeID: cedarlang.LanguagePolicyTypeID,
	}
	treeItem2, err := objects.NewTreeEntry("blob", "bafyreia2d8ccd4b8c9331d762c13a0b2824c121baad579f29f9c16d27146ca1", "name2", objects.TreeDataTypePolicy, meta2)
	require.NoError(t, err, "new tree entry should not return an error")
	_ = tree.AddEntry(treeItem2)

	meta3 := map[string]any{
		objects.MetaKeyCodeID: "code3", objects.MetaKeyCodeTypeID: cedarlang.LanguagePolicyTypeID,
		objects.MetaKeyLanguageID: cedarlang.LanguageCedarJSONID, objects.MetaKeyLanguageVersionID: cedarlang.LanguageSyntaxVersionID, objects.MetaKeyLanguageTypeID: cedarlang.LanguagePolicyTypeID,
	}
	treeItem3, err := objects.NewTreeEntry("tree", "bafyreiafa9b45a58ed64dd7309484a9a4f736930c78b7cb43e23eea22f297e1", "name3", objects.TreeDataTypePolicy, meta3)
	_ = tree.AddEntry(treeItem3)

	require.NoError(t, err, "NewTree should not return an error")

	treeObj, err := objects.CreateTreeObject(tree)
	require.NoError(t, err, "CreateTreeObject should not return an error")
	assert.NotNil(treeObj, "Tree object should not be nil")

	convertedTree, err := objects.ConvertObjectToTree(treeObj)
	require.NoError(t, err, "ConvertObjectToTree should not return an error")
	assert.NotNil(convertedTree, "Converted commit should not be nil")

	assert.Len(convertedTree.Entries(), len(tree.Entries()), "Entries count mismatch")
	for i, entry := range tree.Entries() {
		convertedEntry := convertedTree.Entries()[i]
		assert.Equal(entry.OID(), convertedEntry.OID(), "OID mismatch")
		assert.Equal(entry.OName(), convertedEntry.OName(), "Name mismatch")
		assert.Equal(entry.MetadataString(objects.MetaKeyCodeID), convertedEntry.MetadataString(objects.MetaKeyCodeID), "CodeID mismatch")
		assert.Equal(entry.MetadataUint32(objects.MetaKeyCodeTypeID), convertedEntry.MetadataUint32(objects.MetaKeyCodeTypeID), "CodeTypeID mismatch")
		assert.Equal(entry.MetadataUint32(objects.MetaKeyLanguageID), convertedEntry.MetadataUint32(objects.MetaKeyLanguageID), "LanguageID mismatch")
		assert.Equal(entry.MetadataUint32(objects.MetaKeyLanguageTypeID), convertedEntry.MetadataUint32(objects.MetaKeyLanguageTypeID), "LanguageTypeID mismatch")
		assert.Equal(entry.MetadataUint32(objects.MetaKeyLanguageVersionID), convertedEntry.MetadataUint32(objects.MetaKeyLanguageVersionID), "LanguageVersionID mismatch")
	}
}
