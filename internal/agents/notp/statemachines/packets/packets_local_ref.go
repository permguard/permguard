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

package packets

import (
	"bytes"
	"fmt"

	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
)

// LocalRefStatePacket is the packet to advertise the local ref state.
type LocalRefStatePacket struct {
	// RefCommit is the commit of the local ref.
	RefCommit string
	// HasConflicts is true if the local ref has conflicts with the remote ref.
	HasConflicts bool
	// IsUpToDate is true if the local ref is up to date with the remote ref.
	IsUpToDate bool
}

// GetType returns the type of the packet.
func (p *LocalRefStatePacket) GetType() uint64 {
	return notppackets.CombineUint32toUint64(LocalRefStatePacketType, 0)
}

// Serialize serializes the packet.
func (p *LocalRefStatePacket) Serialize() ([]byte, error) {
	commitBytes := notppackets.EncodeByteArray([]byte(p.RefCommit))

	var hasConflictsByte byte
	if p.HasConflicts {
		hasConflictsByte = 1
	} else {
		hasConflictsByte = 0
	}

	var isUpToDateByte byte
	if p.IsUpToDate {
		isUpToDateByte = 1
	} else {
		isUpToDateByte = 0
	}

	data := append(commitBytes, notppackets.PacketNullByte)
	data = append(data, hasConflictsByte)
	data = append(data, notppackets.PacketNullByte)
	data = append(data, isUpToDateByte)

	return data, nil
}

// Deserialize deserializes the packet.
func (p *LocalRefStatePacket) Deserialize(data []byte) error {
	nullByteIndex := bytes.IndexByte(data, notppackets.PacketNullByte)
	if nullByteIndex == -1 {
		return fmt.Errorf("missing null byte after RefCommit")
	}

	p.RefCommit = string(notppackets.DecodeByteArray(data[:nullByteIndex]))

	if nullByteIndex+1 >= len(data) {
		return fmt.Errorf("missing data for HasConflicts")
	}

	secondNullByteIndex := bytes.IndexByte(data[nullByteIndex+1:], notppackets.PacketNullByte)
	if secondNullByteIndex == -1 {
		return fmt.Errorf("missing null byte after HasConflicts")
	}

	secondNullByteIndex += nullByteIndex + 1

	p.HasConflicts = data[nullByteIndex+1] == 1

	if secondNullByteIndex+1 >= len(data) {
		return fmt.Errorf("missing data for IsUpToDate")
	}

	p.IsUpToDate = data[secondNullByteIndex+1] == 1

	return nil
}
