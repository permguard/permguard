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
}

// GetType returns the type of the packet.
func (p *LocalRefStatePacket) GetType() uint64 {
	return notppackets.CombineUint32toUint64(LocalRefStatePacketType, 0)
}

// Serialize serializes the packet.
func (p *LocalRefStatePacket) Serialize() ([]byte, error) {
	commitBytes := notppackets.EncodeByteArray([]byte(p.RefCommit))

	var boolByte byte
	if p.HasConflicts {
		boolByte = 1
	} else {
		boolByte = 0
	}

	data := append(commitBytes, notppackets.PacketNullByte)
	data = append(data, boolByte)

	return data, nil
}

// Deserialize deserializes the packet.
func (p *LocalRefStatePacket) Deserialize(data []byte) error {
	nullByteIndex := bytes.IndexByte(data, notppackets.PacketNullByte)
	if nullByteIndex == -1 {
		return fmt.Errorf("missing null byte")
	}

	p.RefCommit = string(notppackets.DecodeByteArray(data[:nullByteIndex]))

	if nullByteIndex+1 < len(data) {
		p.HasConflicts = data[nullByteIndex+1] == 1
	} else {
		return fmt.Errorf("missing data for IsLocalRefAhead")
	}

	return nil
}
