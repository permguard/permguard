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

	"github.com/fxamacker/cbor/v2"
)

// objectEnvelope is the CBOR envelope wrapping every stored object.
type objectEnvelope struct {
	Type string `cbor:"1,keyasint"`
	Data []byte `cbor:"2,keyasint"`
}

// ObjectManager is the manager for policies.
type ObjectManager struct {
	encMode cbor.EncMode
	decMode cbor.DecMode
}

// NewObjectManager creates a new ObjectManager.
func NewObjectManager() (*ObjectManager, error) {
	encMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("objects: failed to create cbor encoder: %w", err)
	}
	decMode, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		return nil, fmt.Errorf("objects: failed to create cbor decoder: %w", err)
	}
	return &ObjectManager{
		encMode: encMode,
		decMode: decMode,
	}, nil
}

// createObject wraps typed payload bytes into a CBOR envelope and computes the OID.
func (m *ObjectManager) createObject(objectType string, payload []byte) (*Object, error) {
	env := objectEnvelope{
		Type: objectType,
		Data: payload,
	}
	content, err := m.encMode.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("objects: failed to encode envelope: %w", err)
	}
	return NewObject(content)
}

// CreateCommitObject creates a commit object.
func (m *ObjectManager) CreateCommitObject(commit *Commit) (*Object, error) {
	commitBytes, err := m.SerializeCommit(commit)
	if err != nil {
		return nil, err
	}
	return m.createObject(ObjectTypeCommit, commitBytes)
}

// CreateTreeObject creates a tree object.
func (m *ObjectManager) CreateTreeObject(tree *Tree) (*Object, error) {
	treeBytes, err := m.SerializeTree(tree)
	if err != nil {
		return nil, err
	}
	return m.createObject(ObjectTypeTree, treeBytes)
}

// CreateBlobObject creates a blob object.
func (m *ObjectManager) CreateBlobObject(header *ObjectHeader, data []byte) (*Object, error) {
	if len(data) == 0 {
		return nil, errors.New("objects: data is empty")
	}
	objData, err := m.SerializeBlob(header, data)
	if err != nil {
		return nil, err
	}
	return m.createObject(ObjectTypeBlob, objData)
}

// DeserializeObjectFromBytes deserializes an object from bytes.
func (m *ObjectManager) DeserializeObjectFromBytes(binaryData []byte) (*Object, error) {
	return NewObject(binaryData)
}

// InstanceBytesFromBytes extracts the object type and payload from a CBOR envelope.
func (m *ObjectManager) InstanceBytesFromBytes(object *Object) (string, []byte, error) {
	if object == nil {
		return "", nil, errors.New("objects: object is nil")
	}
	var env objectEnvelope
	if err := m.decMode.Unmarshal(object.content, &env); err != nil {
		return "", nil, fmt.Errorf("objects: failed to decode envelope: %w", err)
	}
	if env.Type == "" {
		return "", nil, errors.New("objects: invalid object envelope: empty type")
	}
	return env.Type, env.Data, nil
}

// ObjectInfo gets the object info.
func (m *ObjectManager) ObjectInfo(object *Object) (*ObjectInfo, error) {
	objectType, instanceBytes, err := m.InstanceBytesFromBytes(object)
	if err != nil {
		return nil, err
	}
	var objectHeader *ObjectHeader
	var instance any
	switch objectType {
	case ObjectTypeCommit:
		commit, err := m.DeserializeCommit(instanceBytes)
		if err != nil {
			return nil, err
		}
		instance = commit
	case ObjectTypeTree:
		tree, err := m.DeserializeTree(instanceBytes)
		if err != nil {
			return nil, err
		}
		instance = tree
	case ObjectTypeBlob:
		header, data, err := m.DeserializeBlob(instanceBytes)
		if err != nil {
			return nil, err
		}
		objectHeader = header
		instance = data
	default:
		return nil, fmt.Errorf("objects: unsupported object type %s", objectType)
	}
	return NewObjectInfo(objectHeader, object, objectType, instanceBytes, instance)
}
