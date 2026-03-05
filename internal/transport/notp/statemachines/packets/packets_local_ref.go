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
	notppkts "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
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
	return notppkts.CombineUint32toUint64(LocalRefStatePacketType, 0)
}

// Serialize serializes the packet.
func (p *LocalRefStatePacket) Serialize() ([]byte, error) {
	data := notppkts.SerializeString(nil, p.RefCommit, notppkts.PacketNullByte)
	data = notppkts.SerializeBool(data, p.HasConflicts, notppkts.PacketNullByte)
	data = notppkts.SerializeBool(data, p.IsUpToDate, notppkts.PacketNullByte)
	data = notppkts.SerializeUint32(data, p.NumberOfCommits, notppkts.PacketNullByte)
	data = notppkts.SerializeUint16(data, p.OpCode, notppkts.PacketNullByte)
	return data, nil
}

// Deserialize deserializes the packet.
func (p *LocalRefStatePacket) Deserialize(data []byte) error {
	var err error
	p.RefCommit, data, err = notppkts.DeserializeString(data, notppkts.PacketNullByte)
	if err != nil {
		return err
	}
	p.HasConflicts, data, err = notppkts.DeserializeBool(data, notppkts.PacketNullByte)
	if err != nil {
		return err
	}
	p.IsUpToDate, data, err = notppkts.DeserializeBool(data, notppkts.PacketNullByte)
	if err != nil {
		return err
	}
	p.NumberOfCommits, data, err = notppkts.DeserializeUint32(data, notppkts.PacketNullByte)
	if err != nil {
		return err
	}
	p.OpCode, _, err = notppkts.DeserializeUint16(data, notppkts.PacketNullByte)
	if err != nil {
		return err
	}
	return nil
}
