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
	"time"
)

// cborCommit is the CBOR-serializable representation of a commit.
type cborCommit struct {
	Tree               string `cbor:"1,keyasint"`
	Parent             string `cbor:"2,keyasint"`
	Author             string `cbor:"3,keyasint"`
	AuthorTimestamp    int64  `cbor:"4,keyasint"`
	Committer          string `cbor:"5,keyasint"`
	CommitterTimestamp int64  `cbor:"6,keyasint"`
	Message            string `cbor:"7,keyasint"`
}

// SerializeCommit serializes a commit object to CBOR.
func (m *ObjectManager) SerializeCommit(commit *Commit) ([]byte, error) {
	if commit == nil {
		return nil, errors.New("objects: commit is nil")
	}
	c := cborCommit{
		Tree:               commit.tree,
		Parent:             commit.parent,
		Author:             commit.metaData.author,
		AuthorTimestamp:    commit.metaData.authorTimestamp.Unix(),
		Committer:          commit.metaData.committer,
		CommitterTimestamp: commit.metaData.committerTimestamp.Unix(),
		Message:            commit.message,
	}
	return m.encMode.Marshal(c)
}

// DeserializeCommit deserializes a commit object from CBOR.
func (m *ObjectManager) DeserializeCommit(data []byte) (*Commit, error) {
	if data == nil {
		return nil, errors.New("objects: data is nil")
	}
	var c cborCommit
	if err := m.decMode.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("objects: failed to decode commit: %w", err)
	}
	return &Commit{
		tree:   c.Tree,
		parent: c.Parent,
		metaData: CommitMetaData{
			author:             c.Author,
			authorTimestamp:    time.Unix(c.AuthorTimestamp, 0),
			committer:          c.Committer,
			committerTimestamp: time.Unix(c.CommitterTimestamp, 0),
		},
		message: c.Message,
	}, nil
}

// BuildCommitHistory builds the commit history iteratively walking from fromCommitID toward toCommitID.
func (m *ObjectManager) BuildCommitHistory(fromCommitID string, toCommitID string, reverse bool, objFunc func(string) (*Object, error)) (bool, []Commit, error) {
	if fromCommitID == ZeroOID && toCommitID == ZeroOID {
		return true, []Commit{}, nil
	}
	var history []Commit
	match := false
	currentID := fromCommitID
	for currentID != ZeroOID {
		commitObj, err := objFunc(currentID)
		if err != nil {
			return false, nil, err
		}
		if commitObj == nil {
			break
		}
		commitObjInfo, err := m.ObjectInfo(commitObj)
		if err != nil {
			return false, nil, err
		}
		commit, ok := commitObjInfo.Instance().(*Commit)
		if !ok {
			return false, nil, fmt.Errorf("objects: invalid object type")
		}
		if commit == nil {
			break
		}
		history = append(history, *commit)
		if commitObj.OID() == toCommitID {
			match = true
			break
		}
		currentID = commit.Parent()
	}
	if reverse {
		for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
			history[i], history[j] = history[j], history[i]
		}
	}
	return match, history, nil
}
