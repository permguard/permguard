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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
)

// TestLanguageSpecification tests the language specification.
func TestLanguageSpecification(t *testing.T) {
	assert := assert.New(t)

	langAbs, err := NewCedarLanguageAbstraction()
	assert.Nil(err, "NewCedarLanguageAbstraction should not return an error")

	langSpec := langAbs.GetLanguageSpecification()
	assert.NotNil(langSpec, "LanguageSpecification should not be nil")
	assert.NotEmpty(langSpec.GetFrontendLanguage(), "LanguageName should not be empty")
	assert.GreaterOrEqual(1, len(langSpec.GetSupportedPolicyFileExtensions()), "SupportedPolicyFileExtensions should not be empty")
	assert.GreaterOrEqual(1, len(langSpec.GetSupportedSchemaFileNames()), "GetSupportedSchemaFileNames should not be empty")
}

// TestCommitCreation tests the commit creation.
func TestCommitCreation(t *testing.T) {
	assert := assert.New(t)

	langAbs, err := NewCedarLanguageAbstraction()
	assert.Nil(err, "NewCedarLanguageAbstraction should not return an error")
	assert.NotNil(langAbs, "Language abstraction should not be nil")

	tree := "4ad3bb52786751f4b6f9839953fe3dcc2278c66648f0d0193f98088b7e4d0c1d"
	parent := "a294ba66f45afd23f8bda3892728601bb509989a80dbb54d7b513dacb8099d76"
	commit, err := azlangobjs.NewCommit(tree, parent, "Nicola Gallo", time.Unix(1628704800, 0), "Nicola Gallo", time.Unix(1628704800, 0), "Initial commit")
	assert.Nil(err, "NewCommit should not return an error")
	assert.NotNil(commit, "Commit should not be nil")

	commitObj, err := langAbs.CreateCommitObject(commit)
	assert.Nil(err, "CreateCommitObject should not return an error")
	assert.NotNil(commitObj, "Commit object should not be nil")

	convertedCommit, err := langAbs.ConvertObjectToCommit(commitObj)
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

	tree, err := azlangobjs.NewTree()

	treeItem1, err := azlangobjs.NewTreeEntry("blob", "515513cd9200cfe899da7ac17a2293ed23a35674b933010d9736e634d3def5fe", "name1", "code1", "codeType1", "cedar", "*", "policy")
	tree.AddEntry(treeItem1)

	treeItem2, err := azlangobjs.NewTreeEntry("blob", "2d8ccd4b8c9331d762c13a0b2824c121baad579f29f9c16d27146ca12d9d6170", "name2", "code2", "codeType2", "cedar", "*", "policy")
	tree.AddEntry(treeItem2)

	treeItem3, err := azlangobjs.NewTreeEntry("tree", "fa9b45a58ed64dd7309484a9a4f736930c78b7cb43e23eea22f297e1bf9ff851", "name3", "code3", "codeType3", "cedar", "*", "policy")
	tree.AddEntry(treeItem3)

	assert.Nil(err, "NewTree should not return an error")

	treeObj, err := langAbs.CreateTreeObject(tree)
	assert.Nil(err, "CreateTreeObject should not return an error")
	assert.NotNil(treeObj, "Tree object should not be nil")

	convertedTree, err := langAbs.ConvertObjectToTree(treeObj)
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

// TestCreateAndReadPolicyBlobObjects tests the creation and reading of policy blob objects.
func TestCreateAndReadPolicyBlobObjects(t *testing.T) {
	assert := assert.New(t)

	langAbs, err := NewCedarLanguageAbstraction()
	assert.Nil(err, "NewCedarLanguageAbstraction should not return an error")
	assert.NotNil(langAbs, "Language abstraction should not be nil")

	path := "./testutils/data/create-blob-objects"

	file1 := `
permit(
	principal in Permguard::Actor::"inventory-auditor",
	action in Action::"view",
	resource in MagicFarmacia::Branch::Inventory::"*"
);`

	file2 := `
@policy_id("assign-role-branch")
permit(
	principal in Permguard::Actor::"administer-branches-staff",
	action in Action::"assignRole",
	resource in MagicFarmacia::Branch::Staff::"*"
)
when {
	principal.active == true &&
	context.id > 0
}
unless {
	principal has isTerminated && principal.isTerminated
};`

	codeFiles := fmt.Sprintln(file1, file2)
	objs, err := langAbs.CreatePolicyBlobObjects(path, []byte(codeFiles))
	assert.Nil(err, "CreatePolicyBlobObjects should not return an error")
	assert.NotNil(objs, "MultiSectionsObject should not be nil")
	assert.Equal(objs.GetNumberOfSections(), 2, "Section objects count mismatch")
	for _, obj := range objs.GetSectionObjects() {
		assert.NotNil(obj, "Object should not be nil")
		assert.Nil(obj.GetError(), "Object error should be nil")
	}
	secObjs := objs.GetSectionObjects()
	assert.Nil(err, "GetNumberOfSections should not return an error")
	assert.NotNil(secObjs, "Section objects should not be nil")
	assert.Equal("view-inventory", secObjs[0].GetCodeID(), "CodeID mismatch")
	assert.Equal("assign-role-branch", secObjs[1].GetCodeID(), "CodeID mismatch")
}
