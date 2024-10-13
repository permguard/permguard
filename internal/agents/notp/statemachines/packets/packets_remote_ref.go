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

// RemoteRefStatePacket is the packet to advertise the remote ref state.
type RemoteRefStatePacket struct {
	// RefPrevCommit is the previous commit of the remote ref.
	RefPrevCommit string
	// RefCommit is the commit of the remote ref.
	RefCommit string
}

// GetType returns the type of the packet.
func (p *RemoteRefStatePacket) GetType() uint64 {
	return notppackets.CombineUint32toUint64(RemoteRefStatePacketType, 0)
}

// Serialize serializes the packet.
func (p *RemoteRefStatePacket) Serialize() ([]byte, error) {
	commitBytes := notppackets.EncodeByteArray([]byte(p.RefPrevCommit))
	prevCommitBytes := notppackets.EncodeByteArray([]byte(p.RefCommit))

	// Aggiungi i campi con byte nullo tra di loro
	data := append(commitBytes, notppackets.PacketNullByte)
	data = append(data, prevCommitBytes...)
	data = append(data, notppackets.PacketNullByte)

	return data, nil
}

// Deserialize deserializes the packet.
func (p *RemoteRefStatePacket) Deserialize(data []byte) error {
	nullByteIndex := bytes.IndexByte(data, notppackets.PacketNullByte)
	if nullByteIndex == -1 {
		return fmt.Errorf("missing null byte after RefCommit")
	}

	p.RefPrevCommit = string(notppackets.DecodeByteArray(data[:nullByteIndex]))

	secondNullByteIndex := bytes.IndexByte(data[nullByteIndex+1:], notppackets.PacketNullByte)
	if secondNullByteIndex == -1 {
		return fmt.Errorf("missing second null byte after RefPrevCommit")
	}

	secondNullByteIndex += nullByteIndex + 1
	p.RefCommit = string(notppackets.DecodeByteArray(data[nullByteIndex+1 : secondNullByteIndex]))

	return nil
}
