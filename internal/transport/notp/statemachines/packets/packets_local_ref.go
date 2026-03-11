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
	aznotppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
)

// LocalRefStatePacket is the packet to advertise the local ref state.
type LocalRefStatePacket struct {
	// RefCommit is the commit of the local ref.
	RefCommit string
	// HasConflicts is true if the local ref has conflicts with the remote ref.
	HasConflicts bool
	// IsUpToDate is true if the local ref is up to date with the remote ref.
	IsUpToDate bool
	// NumberOfCommits is the number of commits between the local ref and the remote ref.
	NumberOfCommits uint32
	// OpCode is the operation code of the packet.
	OpCode uint16
}

// Type returns the type of the packet.
func (p *LocalRefStatePacket) Type() uint64 {
	return aznotppackets.CombineUint32toUint64(LocalRefStatePacketType, 0)
}

// Serialize serializes the packet.
func (p *LocalRefStatePacket) Serialize() ([]byte, error) {
	data := aznotppackets.SerializeString(nil, p.RefCommit, aznotppackets.PacketNullByte)
	data = aznotppackets.SerializeBool(data, p.HasConflicts, aznotppackets.PacketNullByte)
	data = aznotppackets.SerializeBool(data, p.IsUpToDate, aznotppackets.PacketNullByte)
	data = aznotppackets.SerializeUint32(data, p.NumberOfCommits, aznotppackets.PacketNullByte)
	data = aznotppackets.SerializeUint16(data, p.OpCode, aznotppackets.PacketNullByte)
	return data, nil
}

// Deserialize deserializes the packet.
func (p *LocalRefStatePacket) Deserialize(data []byte) error {
	var err error
	p.RefCommit, data, err = aznotppackets.DeserializeString(data, aznotppackets.PacketNullByte)
	if err != nil {
		return err
	}
	p.HasConflicts, data, err = aznotppackets.DeserializeBool(data, aznotppackets.PacketNullByte)
	if err != nil {
		return err
	}
	p.IsUpToDate, data, err = aznotppackets.DeserializeBool(data, aznotppackets.PacketNullByte)
	if err != nil {
		return err
	}
	p.NumberOfCommits, data, err = aznotppackets.DeserializeUint32(data, aznotppackets.PacketNullByte)
	if err != nil {
		return err
	}
	p.OpCode, _, err = aznotppackets.DeserializeUint16(data, aznotppackets.PacketNullByte)
	if err != nil {
		return err
	}
	return nil
}
