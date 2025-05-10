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
)

// SerializeCommit serializes a commit object.
func (m *ObjectManager) SerializeCommit(commit *Commit) ([]byte, error) {
	if commit == nil {
		return nil, errors.New("objects: commit is nil")
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("tree %s\n", commit.tree))
	sb.WriteString(fmt.Sprintf("parent %s\n", commit.parent))
	sb.WriteString(fmt.Sprintf("author %s %s\n", commit.metaData.authorTimestamp.Format(time.RFC3339), commit.metaData.author))
	sb.WriteString(fmt.Sprintf("committer %s %s\n", commit.metaData.committerTimestamp.Format(time.RFC3339), commit.metaData.committer))
	sb.WriteString(commit.message)
	return []byte(sb.String()), nil
}

// parseIdentity parses the identity line.
func (m *ObjectManager) parseIdentity(line string) (string, time.Time) {
	parts := strings.Split(line, " ")
	if len(parts) < 2 {
		return "", time.Time{}
	}
	datePart := parts[0]
	parsedTime, _ := time.Parse(time.RFC3339, datePart)

	identityPart := strings.Join(parts[1:], " ")
	return identityPart, parsedTime
}

// DeserializeCommit deserializes a commit object.
func (m *ObjectManager) DeserializeCommit(data []byte) (*Commit, error) {
	if data == nil {
		return nil, errors.New("objects: data is nil")
	}
	inputStr := string(data)
	lines := strings.Split(inputStr, "\n")
	commit := &Commit{}
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(line, "tree ") {
			commit.tree = strings.TrimPrefix(line, "tree ")
		} else if strings.HasPrefix(line, "parent ") {
			commit.parent = strings.TrimPrefix(line, "parent ")
		} else if strings.HasPrefix(line, "author ") {
			author, date := m.parseIdentity(strings.TrimPrefix(line, "author "))
			commit.metaData.author = author
			commit.metaData.authorTimestamp = date
		} else if strings.HasPrefix(line, "committer ") {
			committer, date := m.parseIdentity(strings.TrimPrefix(line, "committer "))
			commit.metaData.committer = committer
			commit.metaData.committerTimestamp = date
		} else if i == len(lines)-1 {
			commit.message = line
		}
	}
	return commit, nil
}

// buildCommitHistory builds the commit history.
func (m *ObjectManager) buildCommitHistory(fromCommitID string, toCommitID string, match bool, history []Commit, objFunc func(string) (*Object, error)) (bool, []Commit, error) {
	if fromCommitID == ZeroOID && toCommitID == ZeroOID {
		match = true
		return match, history, nil
	}
	var commitObj *Object
	var err error
	if fromCommitID != ZeroOID {
		commitObj, err = objFunc(fromCommitID)
		if err != nil {
			return false, nil, err
		}
	}
	var commit *Commit
	if commitObj != nil {
		commitObjInfo, err := m.GetObjectInfo(commitObj)
		if err != nil {
			return false, nil, err
		}
		var ok bool
		commit, ok = commitObjInfo.GetInstance().(*Commit)
		if !ok {
			return false, nil, fmt.Errorf("objects: invalid object type")
		}
		if commit != nil {
			history = append(history, *commit)
		}
	}
	if commitObj == nil || commit == nil {
		return match, history, nil
	}
	if commitObj.GetOID() == toCommitID {
		match = true
		return match, history, nil
	}
	return m.buildCommitHistory(commit.GetParent(), toCommitID, match, history, objFunc)
}

// BuildCommitHistory builds the commit history.
func (m *ObjectManager) BuildCommitHistory(fromCommitID string, toCommitID string, reverse bool, objFunc func(string) (*Object, error)) (bool, []Commit, error) {
	if fromCommitID == ZeroOID && toCommitID != ZeroOID {
		return false, nil, fmt.Errorf("objects: invalid from commit ID")
	}
	match, history, err := m.buildCommitHistory(fromCommitID, toCommitID, false, []Commit{}, objFunc)
	if err == nil && reverse {
		for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
			history[i], history[j] = history[j], history[i]
		}
	}
	return match, history, err
}
