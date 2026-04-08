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
	"fmt"
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
	// ZeroOID represents the zero oid.
	// It is a CIDv1 with dag-cbor codec and an all-zero SHA2-256 digest,
	// used as a sentinel value representing the absence of content.
	ZeroOID = "bafyreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// DataTypeUnknown represents an unknown data type.
	DataTypeUnknown uint32 = 0
	// DataTypeManifest represents a manifest data type.
	DataTypeManifest uint32 = 1
	// DataTypeAbstractTree represents an abstract/parsed representation of the content.
	DataTypeAbstractTree uint32 = 2
	// DataTypeSourceLanguage represents source code in the policy language.
	DataTypeSourceLanguage uint32 = 3

	// TreeDataTypeUnknown represents an unknown tree entry data type.
	TreeDataTypeUnknown uint32 = 0
	// TreeDataTypeManifest represents a manifest tree entry data type.
	TreeDataTypeManifest uint32 = 1
	// TreeDataTypePolicy represents a policy tree entry data type.
	TreeDataTypePolicy uint32 = 2

	// MetaKeyPartition is the metadata key for the partition.
	MetaKeyPartition = "partition"
	// MetaKeyLanguageID is the metadata key for the language ID.
	MetaKeyLanguageID = "language-id"
	// MetaKeyLanguageVersionID is the metadata key for the language version ID.
	MetaKeyLanguageVersionID = "language-version-id"
	// MetaKeyLanguageTypeID is the metadata key for the language type ID.
	MetaKeyLanguageTypeID = "language-type-id"
	// MetaKeyCodeID is the metadata key for the code ID.
	MetaKeyCodeID = "code-id"
	// MetaKeyCodeTypeID is the metadata key for the code type ID.
	MetaKeyCodeTypeID = "code-type-id"
	// MetaKeyFormat is the metadata key for the content format.
	MetaKeyFormat = "format"
)

// DataTypeName returns the display name for a content kind ID.
// Falls back to the decimal string representation for unknown IDs.
func DataTypeName(id uint32) string {
	switch id {
	case DataTypeUnknown:
		return "unknown"
	case DataTypeManifest:
		return "manifest"
	case DataTypeAbstractTree:
		return "ast"
	case DataTypeSourceLanguage:
		return "source"
	default:
		return fmt.Sprintf("%d", id)
	}
}

// TreeDataTypeName returns the display name for a tree entry data type ID.
func TreeDataTypeName(id uint32) string {
	switch id {
	case TreeDataTypeUnknown:
		return "unknown"
	case TreeDataTypeManifest:
		return "manifest"
	case TreeDataTypePolicy:
		return "policy"
	default:
		return fmt.Sprintf("%d", id)
	}
}

// ObjectHeader represents the object header.
type ObjectHeader struct {
	dataType uint32
	metadata map[string]any
}

// DataType returns the data type of the object.
func (o *ObjectHeader) DataType() uint32 {
	return o.dataType
}

// Metadata returns the metadata map of the object.
func (o *ObjectHeader) Metadata() map[string]any {
	return o.metadata
}

// MetadataString returns a metadata value as a string.
// Returns an empty string if the key is missing or not a string.
func (o *ObjectHeader) MetadataString(key string) string {
	v, ok := o.metadata[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// MetadataUint32 returns a metadata value as a uint32.
// Returns 0 if the key is missing or not a uint32.
func (o *ObjectHeader) MetadataUint32(key string) uint32 {
	v, ok := o.metadata[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case uint32:
		return n
	case uint64:
		return uint32(n)
	case int64:
		return uint32(n)
	case float64:
		return uint32(n)
	default:
		return 0
	}
}

// NewObjectHeader creates a new object header.
func NewObjectHeader(dataType uint32, metadata map[string]any) (*ObjectHeader, error) {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	return &ObjectHeader{
		dataType: dataType,
		metadata: metadata,
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
	oid, err := crypto.ComputeCID(content)
	if err != nil {
		return nil, err
	}
	return &Object{
		oid:     oid,
		content: content,
	}, nil
}

// ObjectInfo is the object info.
type ObjectInfo struct {
	header        *ObjectHeader
	otype         string
	object        *Object
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

// CommitProfile represents a profile entry in a commit, mapping a profile/partition key to a tree.
type CommitProfile struct {
	key  string
	tree CID
}

// NewCommitProfile creates a new commit profile.
func NewCommitProfile(key string, tree CID) (*CommitProfile, error) {
	if key == "" {
		return nil, errors.New("objects: commit profile key is empty")
	}
	if !tree.IsValid() {
		return nil, errors.New("objects: commit profile tree CID is invalid")
	}
	return &CommitProfile{key: key, tree: tree}, nil
}

// Key returns the profile key (e.g. "profilename/partition").
func (p *CommitProfile) Key() string {
	return p.key
}

// Tree returns the tree CID for this profile.
func (p *CommitProfile) Tree() CID {
	return p.tree
}

// Commit represents a commit object.
type Commit struct {
	profiles    []CommitProfile
	manifest    CID
	predecessor NullableString
	metaData    CommitMetaData
	message     string
}

// Profiles returns the profiles of the commit.
func (c *Commit) Profiles() []CommitProfile {
	cp := make([]CommitProfile, len(c.profiles))
	copy(cp, c.profiles)
	return cp
}

// Manifest returns the manifest CID of the commit.
func (c *Commit) Manifest() CID {
	return c.manifest
}

// Predecessor returns the OID of the predecessor commit, or nil for the root commit.
func (c *Commit) Predecessor() NullableString {
	return c.predecessor
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
// predecessorCommitID is nil for a root commit (no predecessor).
func NewCommit(profiles []CommitProfile, manifest CID, predecessorCommitID NullableString, author string, authorTimestamp time.Time, committer string, committerTimestamp time.Time, message string) (*Commit, error) {
	if len(profiles) == 0 {
		return nil, errors.New("objects: commit must have at least one profile")
	}
	for i := range profiles {
		if !profiles[i].tree.IsValid() {
			return nil, fmt.Errorf("objects: profile %q has invalid tree CID", profiles[i].key)
		}
	}
	if !manifest.IsValid() {
		return nil, errors.New("objects: manifest CID is invalid")
	}
	if predecessorCommitID.Valid && !CID(predecessorCommitID.String).IsValid() {
		return nil, errors.New("objects: predecessor commit CID is invalid")
	}
	if authorTimestamp.Equal((time.Time{})) {
		authorTimestamp = time.Now()
	}
	if committerTimestamp.Equal((time.Time{})) {
		committerTimestamp = time.Now()
	}
	return &Commit{
		profiles:    profiles,
		manifest:    manifest,
		predecessor: predecessorCommitID,
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
	otype    string
	oid      string
	oname    string
	dataType uint32
	metadata map[string]any
}

// NewTreeEntry creates a new tree entry.
func NewTreeEntry(otype, oid, oname string, dataType uint32, metadata map[string]any) (*TreeEntry, error) {
	if strings.TrimSpace(otype) == "" {
		return nil, errors.New("objects: object type is empty")
	} else if strings.TrimSpace(oid) == "" {
		return nil, errors.New("objects: object id is empty")
	} else if strings.TrimSpace(oname) == "" {
		return nil, errors.New("objects: object name is empty")
	}
	if metadata == nil {
		metadata = make(map[string]any)
	}
	return &TreeEntry{
		otype:    otype,
		oid:      oid,
		oname:    oname,
		dataType: dataType,
		metadata: metadata,
	}, nil
}

// DataType returns the data type of the tree entry.
func (t *TreeEntry) DataType() uint32 {
	return t.dataType
}

// OType returns the object type of the tree entry.
func (t *TreeEntry) OType() string {
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

// Metadata returns the metadata map of the tree entry.
func (t *TreeEntry) Metadata() map[string]any {
	return t.metadata
}

// MetadataString returns a metadata value as a string.
func (t *TreeEntry) MetadataString(key string) string {
	v, ok := t.metadata[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// MetadataUint32 returns a metadata value as a uint32.
func (t *TreeEntry) MetadataUint32(key string) uint32 {
	v, ok := t.metadata[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case uint32:
		return n
	case uint64:
		return uint32(n)
	case int64:
		return uint32(n)
	case float64:
		return uint32(n)
	default:
		return 0
	}
}

// Tree represents a tree object.
type Tree struct {
	partition string
	entries   []TreeEntry
}

// NewTree creates a new tree object.
func NewTree(partition string) (*Tree, error) {
	if strings.TrimSpace(partition) == "" {
		return nil, errors.New("objects: partition is empty")
	}
	return &Tree{
		partition: partition,
		entries:   make([]TreeEntry, 0),
	}, nil
}

// Partition returns the partition of the tree.
func (t *Tree) Partition() string {
	return t.partition
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
		if e.MetadataString(MetaKeyCodeID) == entry.MetadataString(MetaKeyCodeID) && e.MetadataUint32(MetaKeyCodeTypeID) == entry.MetadataUint32(MetaKeyCodeTypeID) {
			return errors.New("objects: tree entry already exists")
		}
	}
	t.entries = append(t.entries, *entry)
	return nil
}
