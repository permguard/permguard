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
	"errors"
	"strings"
	"time"

	"github.com/permguard/permguard/common/pkg/extensions/copier"
	"github.com/permguard/permguard/common/pkg/extensions/crypto"
)

const (
	// ObjectTypeCommit is the object type for a commit.
	ObjectTypeCommit = "commit"
	// ObjectTypeTree is the object type for a tree.
	ObjectTypeTree = "tree"
	// ObjectTypeBlob is the object type for a blob.
	ObjectTypeBlob = "blob"
	// ZeroOID  represents the zero oid
	ZeroOID = "0000000000000000000000000000000000000000000000000000000000000000"
)

// ObjectHeader represents the object header.
type ObjectHeader struct {
	isNativeLanguage  bool
	partition         string
	languageID        uint32
	languageVersionID uint32
	languageTypeID    uint32
	codeID            string
	codeTypeID        uint32
}

// GetPartition returns the partition of the object.
func (o *ObjectHeader) GetPartition() string {
	return o.partition
}

// IsNativeLanguage returns true if the object is in a native language.
func (o *ObjectHeader) IsNativeLanguage() bool {
	return o.isNativeLanguage
}

// GetLanguageID returns the language ID of the object.
func (o *ObjectHeader) GetLanguageID() uint32 {
	return o.languageID
}

// GetLanguageVersionID returns the language version ID of the object.
func (o *ObjectHeader) GetLanguageVersionID() uint32 {
	return o.languageVersionID
}

// GetLanguageTypeID returns the language type ID of the object.
func (o *ObjectHeader) GetLanguageTypeID() uint32 {
	return o.languageTypeID
}

// GetCodeID returns the code ID of the object.
func (o *ObjectHeader) GetCodeID() string {
	return o.codeID
}

// GetCodeTypeID returns the code type ID of the object.
func (o *ObjectHeader) GetCodeTypeID() uint32 {
	return o.codeTypeID
}

// NewObjectHeader creates a new object header.
func NewObjectHeader(partition string, isNativeLanguage bool, languageID, languageVersionID, languageTypeID uint32, codeID string, codeTypeID uint32) (*ObjectHeader, error) {
	return &ObjectHeader{
		partition:         partition,
		isNativeLanguage:  isNativeLanguage,
		languageID:        languageID,
		languageVersionID: languageVersionID,
		languageTypeID:    languageTypeID,
		codeID:            codeID,
		codeTypeID:        codeTypeID,
	}, nil
}

// Object represents the object.
type Object struct {
	oid     string
	content []byte
}

// GetOID returns the OID of the object.
func (o *Object) GetOID() string {
	return o.oid
}

// GetContent returns the content of the object.
func (o *Object) GetContent() []byte {
	return o.content
}

// NewObject creates a new object.
func NewObject(content []byte) (*Object, error) {
	if content == nil {
		return nil, errors.New("objects: object content is nil")
	}
	return &Object{
		oid:     crypto.ComputeSHA256(content),
		content: content,
	}, nil
}

// ObjectInfo is the object info.
type ObjectInfo struct {
	header        *ObjectHeader
	object        *Object
	otype         string
	instanceBytes []byte
	instance      any
}

// GetOID returns the OID of the object.
func (o *ObjectInfo) GetOID() string {
	if o.object == nil {
		return ""
	}
	return o.object.oid
}

// GetHeader returns the header of the object.
func (o *ObjectInfo) GetHeader() *ObjectHeader {
	return o.header
}

// GetObject returns the object.
func (o *ObjectInfo) GetObject() *Object {
	return o.object
}

// GetType returns the type of the object.
func (o *ObjectInfo) GetType() string {
	return o.otype
}

// GetInstanceBytes returns the instance bytes of the object.
func (o *ObjectInfo) GetInstanceBytes() []byte {
	return o.instanceBytes
}

// GetInstance returns the instance of the object.
func (o *ObjectInfo) GetInstance() any {
	return o.instance
}

// NewObjectInfo creates a new object info.
func NewObjectInfo(header *ObjectHeader, object *Object, otype string, instanceBytes []byte, instance any) (*ObjectInfo, error) {
	if object == nil {
		return nil, errors.New("objects: object content is nil")
	} else if strings.TrimSpace(otype) == "" {
		return nil, errors.New("objects: object type is empty")
	} else if instance == nil {
		return nil, errors.New("objects: object instance is nil")
	}
	return &ObjectInfo{
		header:        header,
		object:        object,
		otype:         otype,
		instanceBytes: instanceBytes,
		instance:      instance,
	}, nil
}

// CommitMetaData represents commit's metadata.
type CommitMetaData struct {
	author             string
	authorTimestamp    time.Time
	committer          string
	committerTimestamp time.Time
}

// GetAuthor returns the author of the commit info.
func (c *CommitMetaData) GetAuthor() string {
	return c.author
}

// GetAuthorTimestamp returns the author timestamp of the commit info.
func (c *CommitMetaData) GetAuthorTimestamp() time.Time {
	return c.authorTimestamp
}

// GetCommitter returns the committer of the commit info.
func (c *CommitMetaData) GetCommitter() string {
	return c.committer
}

// GetCommitterTimestamp returns the committer timestamp of the commit info.
func (c *CommitMetaData) GetCommitterTimestamp() time.Time {
	return c.committerTimestamp
}

// Commit represents a commit object.
type Commit struct {
	tree     string
	parent   string
	metaData CommitMetaData
	message  string
}

// GetTree returns the tree of the commit.
func (c *Commit) GetTree() string {
	return c.tree
}

// GetParent return the parent of the commit.
func (c *Commit) GetParent() string {
	return c.parent
}

// GetMetaData returns the metadata of the commit.
func (c *Commit) GetMetaData() CommitMetaData {
	return c.metaData
}

// GetMessage returns the message of the commit.
func (c *Commit) GetMessage() string {
	return c.message
}

// NewCommit creates a new commit object.
func NewCommit(tree string, parentCommitID string, author string, authorTimestamp time.Time, committer string, committerTimestamp time.Time, message string) (*Commit, error) {
	if strings.TrimSpace(tree) == "" {
		return nil, errors.New("objects: tree is empty")
	} else if strings.TrimSpace(parentCommitID) == "" {
		return nil, errors.New("objects: parent commit id is empty")
	}
	if strings.TrimSpace(author) == "" {
		author = "unknown"
	}
	if authorTimestamp == (time.Time{}) {
		authorTimestamp = time.Now()
	}
	if strings.TrimSpace(committer) == "" {
		committer = "unknown"
	}
	if committerTimestamp == (time.Time{}) {
		committerTimestamp = time.Now()
	}
	return &Commit{
		tree:   tree,
		parent: parentCommitID,
		metaData: CommitMetaData{
			author:             author,
			authorTimestamp:    authorTimestamp,
			committer:          committer,
			committerTimestamp: committerTimestamp,
		},
		message: message,
	}, nil
}

// TreeEntry represents a single entry in a tree object.
type TreeEntry struct {
	partition       string
	otype           string
	oid             string
	oname           string
	codeID          string
	codeType        string
	langauge        string
	langaugeVersion string
	langaugeType    string
}

// NewTreeEntry creates a new tree entry.
func NewTreeEntry(partition, otype, oid, oname, codeID, codeType, langauge, langaugeVersion, langaugeType string) (*TreeEntry, error) {
	if strings.TrimSpace(partition) == "" {
		return nil, errors.New("objects: object type is empty")
	} else if strings.TrimSpace(otype) == "" {
		return nil, errors.New("objects: object type is empty")
	} else if strings.TrimSpace(oid) == "" {
		return nil, errors.New("objects: object id is empty")
	} else if strings.TrimSpace(oname) == "" {
		return nil, errors.New("objects: object name is empty")
	} else if strings.TrimSpace(codeID) == "" {
		return nil, errors.New("objects: code id is empty")
	} else if strings.TrimSpace(codeType) == "" {
		return nil, errors.New("objects: code name is empty")
	} else if strings.TrimSpace(langauge) == "" {
		return nil, errors.New("objects: language is empty")
	} else if strings.TrimSpace(langaugeVersion) == "" {
		return nil, errors.New("objects: language version is empty")
	} else if strings.TrimSpace(langaugeType) == "" {
		return nil, errors.New("objects: language type is empty")
	}
	return &TreeEntry{
		partition:       partition,
		otype:           otype,
		oid:             oid,
		oname:           oname,
		codeID:          codeID,
		codeType:        codeType,
		langauge:        langauge,
		langaugeVersion: langaugeVersion,
		langaugeType:    langaugeType,
	}, nil
}

// GetPartition returns the partition of the tree entry.
func (t *TreeEntry) GetPartition() string {
	return t.partition
}

// GetType returns the type of the tree entry.
func (t *TreeEntry) GetType() string {
	return t.otype
}

// GetOID returns the OID of the tree entry.
func (t *TreeEntry) GetOID() string {
	return t.oid
}

// GetOName returns the object name of the tree entry.
func (t *TreeEntry) GetOName() string {
	return t.oname
}

// GetCodeID returns the code ID of the tree entry.
func (t *TreeEntry) GetCodeID() string {
	return t.codeID
}

// GetCodeType returns the code name of the tree entry.
func (t *TreeEntry) GetCodeType() string {
	return t.codeType
}

// GetLanguage returns the language of the tree entry.
func (t *TreeEntry) GetLanguage() string {
	return t.langauge
}

// GetLanguageVersion returns the language version of the tree entry.
func (t *TreeEntry) GetLanguageVersion() string {
	return t.langaugeVersion
}

// GetLanguageType returns the language type of the tree entry.
func (t *TreeEntry) GetLanguageType() string {
	return t.langaugeType
}

// Tree represents a tree object.
type Tree struct {
	entries []TreeEntry
}

// NewTree creates a new tree object.
func NewTree() (*Tree, error) {
	return &Tree{
		entries: make([]TreeEntry, 0),
	}, nil
}

// GetEntries returns the entries of the tree.
func (t *Tree) GetEntries() []TreeEntry {
	return copier.CopySlice(t.entries)
}

// AddEntry adds an entry to the tree.
func (t *Tree) AddEntry(entry *TreeEntry) error {
	if entry == nil {
		return errors.New("objects: tree entry is nil")
	}
	for _, e := range t.entries {
		if e.GetOName() == entry.GetOName() {
			return errors.New("objects: tree entry already exists")
		}
		if e.GetCodeID() == entry.GetCodeID() && e.GetCodeType() == entry.GetCodeType() {
			return errors.New("objects: tree entry already exists")
		}
	}
	t.entries = append(t.entries, *entry)
	return nil
}
