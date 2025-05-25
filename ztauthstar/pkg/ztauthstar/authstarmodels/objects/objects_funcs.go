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
)

// ReadObjectContentBytes reads the object content bytes.
func ReadObjectContentBytes(obj *Object) (uint32, []byte, error) {
	objMng, err := NewObjectManager()
	if err != nil {
		return 0, nil, err
	}
	objInfo, err := objMng.GetObjectInfo(obj)
	if err != nil {
		return 0, nil, err
	}
	objHeader := objInfo.GetHeader()
	if !objHeader.IsNativeLanguage() {
		return 0, nil, errors.New("objects: object is not in native language")
	}
	instance, ok := objInfo.GetInstance().([]byte)
	if !ok {
		return 0, nil, errors.New("objects: invalid object instance")
	}
	return objHeader.GetCodeTypeID(), instance, nil
}

// CreateCommitObject creates a commit object.
func CreateCommitObject(commit *Commit) (*Object, error) {
	objMng, err := NewObjectManager()
	if err != nil {
		return nil, err
	}
	return objMng.CreateCommitObject(commit)
}

// ConvertObjectToCommit converts an object to a commit.
func ConvertObjectToCommit(obj *Object) (*Commit, error) {
	objMng, err := NewObjectManager()
	if err != nil {
		return nil, err
	}
	objInfo, err := objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, fmt.Errorf("objects: failed to get the object info %w", err)
	}

	value, ok := objInfo.GetInstance().(*Commit)
	if !ok {
		return nil, errors.New("objects: object is not a valid commit")
	}
	return value, nil
}

// CreateTreeObject creates a tree object.
func CreateTreeObject(tree *Tree) (*Object, error) {
	objMng, err := NewObjectManager()
	if err != nil {
		return nil, err
	}
	return objMng.CreateTreeObject(tree)
}

// ConvertObjectToTree converts an object to a tree.
func ConvertObjectToTree(obj *Object) (*Tree, error) {
	objMng, err := NewObjectManager()
	if err != nil {
		return nil, err
	}
	objInfo, err := objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, fmt.Errorf("objects: failed to get the object info %w", err)
	}

	value, ok := objInfo.GetInstance().(*Tree)
	if !ok {
		return nil, errors.New("objects: object is not a valid tree")
	}
	return value, nil
}
