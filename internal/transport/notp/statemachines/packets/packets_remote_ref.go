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
	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
)

// RemoteRefStatePacket is the packet to advertise the remote ref state.
type RemoteRefStatePacket struct {
	// RefPrevCommit is the previous commit of the remote ref.
	RefPrevCommit string
	// RefCommit is the commit of the remote ref.
	RefCommit string
	// OpCode is the operation code of the packet.
	OpCode uint16
}

// Type returns the type of the packet.
func (p *RemoteRefStatePacket) Type() uint64 {
	return notppackets.CombineUint32toUint64(RemoteRefStatePacketType, 0)
}

// Serialize serializes the packet.
func (p *RemoteRefStatePacket) Serialize() ([]byte, error) {
	data := notppackets.SerializeString(nil, p.RefPrevCommit, notppackets.PacketNullByte)
	data = notppackets.SerializeString(data, p.RefCommit, notppackets.PacketNullByte)
	data = notppackets.SerializeUint16(data, p.OpCode, notppackets.PacketNullByte)
	return data, nil
}

// Deserialize deserializes the packet.
func (p *RemoteRefStatePacket) Deserialize(data []byte) error {
	var err error
	p.RefPrevCommit, data, err = notppackets.DeserializeString(data, notppackets.PacketNullByte)
	if err != nil {
		return err
	}
	p.RefCommit, data, err = notppackets.DeserializeString(data, notppackets.PacketNullByte)
	if err != nil {
		return err
	}
	p.OpCode, _, err = notppackets.DeserializeUint16(data, notppackets.PacketNullByte)
	if err != nil {
		return err
	}
	return nil
}
