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

// ObjectStatePacket is object state description packet.
type ObjectStatePacket struct {
	// OID is the OID.
	OID string
	// OType is the object type.
	OType string
	// Content is the object content.
	Content []byte
}

// GetType returns the type of the packet.
func (p *ObjectStatePacket) GetType() uint64 {
	return notppackets.CombineUint32toUint64(ObjectStatePacketType, 0)
}

// Serialize serializes the packet.
func (p *ObjectStatePacket) Serialize() ([]byte, error) {
	data := notppackets.SerializeString(nil, p.OID, notppackets.PacketNullByte)
	data = notppackets.SerializeString(data, p.OType, notppackets.PacketNullByte)
	data = notppackets.SerializeBytes(data, p.Content, notppackets.PacketNullByte)
	return data, nil
}

// Deserialize deserializes the packet.
func (p *ObjectStatePacket) Deserialize(data []byte) error {
	var err error
	p.OID, data, err = notppackets.DeserializeString(data, notppackets.PacketNullByte)
	if err != nil {
		return err
	}
	p.OType, data, err = notppackets.DeserializeString(data, notppackets.PacketNullByte)
	if err != nil {
		return err
	}
	p.Content, data, err = notppackets.DeserializeBytes(data, notppackets.PacketNullByte)
	if err != nil {
		return err
	}
	return nil
}
