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
	"encoding/binary"
	"fmt"
	"unsafe"

	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
)

// LocalRefStatePacket is the packet to advertise the local ref state.
type LocalRefStatePacket struct {
	// RefCommit is the commit of the local ref.
	RefCommit string
	// RemoteRefTimestamp is the timestamp of the remote ref.
	RemoteRefTimestamp uint64
}

// GetType returns the type of the packet.
func (p *LocalRefStatePacket) GetType() uint64 {
	return notppackets.CombineUint32toUint64(LocalRefStatePacketType, 0)
}

// Serialize serializes the packet.
func (p *LocalRefStatePacket) Serialize() ([]byte, error) {
	commitBytes := notppackets.EncodeByteArray([]byte(p.RefCommit))

	idSize := int(unsafe.Sizeof(p.RemoteRefTimestamp))
	timestampBytes := make([]byte, idSize)
	binary.BigEndian.PutUint64(timestampBytes, p.RemoteRefTimestamp)

	data := append(commitBytes, notppackets.PacketNullByte)
	data = append(data, timestampBytes...)

	return data, nil
}

// Deserialize deserializes the packet.
func (p *LocalRefStatePacket) Deserialize(data []byte) error {
	nullByteIndex := bytes.IndexByte(data, notppackets.PacketNullByte)
	if nullByteIndex == -1 {
		return fmt.Errorf("missing null byte")
	}

	p.RefCommit = string(data[:nullByteIndex])

	idSize := int(unsafe.Sizeof(uint64(0)))
	if nullByteIndex+1+idSize <= len(data) {
		p.RemoteRefTimestamp = binary.BigEndian.Uint64(data[nullByteIndex+1 : nullByteIndex+9])
	} else {
		return fmt.Errorf("missing data for RemoteTimestamp")
	}

	return nil
}
