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

// Partition returns the partition of the object.
func (o *ObjectHeader) Partition() string {
	return o.partition
}

// IsNativeLanguage returns true if the object is in a native language.
func (o *ObjectHeader) IsNativeLanguage() bool {
	return o.isNativeLanguage
}

// LanguageID returns the language ID of the object.
func (o *ObjectHeader) LanguageID() uint32 {
	return o.languageID
}

// LanguageVersionID returns the language version ID of the object.
func (o *ObjectHeader) LanguageVersionID() uint32 {
	return o.languageVersionID
}

// LanguageTypeID returns the language type ID of the object.
func (o *ObjectHeader) LanguageTypeID() uint32 {
	return o.languageTypeID
}

// CodeID returns the code ID of the object.
func (o *ObjectHeader) CodeID() string {
	return o.codeID
}

// CodeTypeID returns the code type ID of the object.
func (o *ObjectHeader) CodeTypeID() uint32 {
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

// OID returns the OID of the object.
func (o *Object) OID() string {
	return o.oid
}

// Content returns the content of the object.
func (o *Object) Content() []byte {
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

// OID returns the OID of the object.
func (o *ObjectInfo) OID() string {
	if o.object == nil {
		return ""
	}
	return o.object.oid
}

// Header returns the header of the object.
func (o *ObjectInfo) Header() *ObjectHeader {
	return o.header
}

// Object returns the object.
func (o *ObjectInfo) Object() *Object {
	return o.object
}

// Type returns the type of the object.
func (o *ObjectInfo) Type() string {
	return o.otype
}

// InstanceBytes returns the instance bytes of the object.
func (o *ObjectInfo) InstanceBytes() []byte {
	return o.instanceBytes
}

// Instance returns the instance of the object.
func (o *ObjectInfo) Instance() any {
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

// Author returns the author of the commit info.
func (c *CommitMetaData) Author() string {
	return c.author
}

// AuthorTimestamp returns the author timestamp of the commit info.
func (c *CommitMetaData) AuthorTimestamp() time.Time {
	return c.authorTimestamp
}

// Committer returns the committer of the commit info.
func (c *CommitMetaData) Committer() string {
	return c.committer
}

// CommitterTimestamp returns the committer timestamp of the commit info.
func (c *CommitMetaData) CommitterTimestamp() time.Time {
	return c.committerTimestamp
}

// Commit represents a commit object.
type Commit struct {
	tree     string
	parent   string
	metaData CommitMetaData
	message  string
}

// Tree returns the tree of the commit.
func (c *Commit) Tree() string {
	return c.tree
}

// Parent return the parent of the commit.
func (c *Commit) Parent() string {
	return c.parent
}

// MetaData returns the metadata of the commit.
func (c *Commit) MetaData() CommitMetaData {
	return c.metaData
}

// Message returns the message of the commit.
func (c *Commit) Message() string {
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
	if authorTimestamp.Equal((time.Time{})) {
		authorTimestamp = time.Now()
	}
	if strings.TrimSpace(committer) == "" {
		committer = "unknown"
	}
	if committerTimestamp.Equal((time.Time{})) {
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

// Partition returns the partition of the tree entry.
func (t *TreeEntry) Partition() string {
	return t.partition
}

// Type returns the type of the tree entry.
func (t *TreeEntry) Type() string {
	return t.otype
}

// OID returns the OID of the tree entry.
func (t *TreeEntry) OID() string {
	return t.oid
}

// OName returns the object name of the tree entry.
func (t *TreeEntry) OName() string {
	return t.oname
}

// CodeID returns the code ID of the tree entry.
func (t *TreeEntry) CodeID() string {
	return t.codeID
}

// CodeType returns the code name of the tree entry.
func (t *TreeEntry) CodeType() string {
	return t.codeType
}

// Language returns the language of the tree entry.
func (t *TreeEntry) Language() string {
	return t.langauge
}

// LanguageVersion returns the language version of the tree entry.
func (t *TreeEntry) LanguageVersion() string {
	return t.langaugeVersion
}

// LanguageType returns the language type of the tree entry.
func (t *TreeEntry) LanguageType() string {
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

// Entries returns the entries of the tree.
func (t *Tree) Entries() []TreeEntry {
	return copier.CopySlice(t.entries)
}

// AddEntry adds an entry to the tree.
func (t *Tree) AddEntry(entry *TreeEntry) error {
	if entry == nil {
		return errors.New("objects: tree entry is nil")
	}
	for _, e := range t.entries {
		if e.OName() == entry.OName() {
			return errors.New("objects: tree entry already exists")
		}
		if e.CodeID() == entry.CodeID() && e.CodeType() == entry.CodeType() {
			return errors.New("objects: tree entry already exists")
		}
	}
	t.entries = append(t.entries, *entry)
	return nil
}
