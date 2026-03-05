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

// ObjectStatePacket is object state description packet.
type ObjectStatePacket struct {
	// OID is the OID.
	OID string
	// OType is the object type.
	OType string
	// Content is the object content.
	Content []byte
}

// Type returns the type of the packet.
func (p *ObjectStatePacket) Type() uint64 {
	return notppkts.CombineUint32toUint64(ObjectStatePacketType, 0)
}

// Serialize serializes the packet.
func (p *ObjectStatePacket) Serialize() ([]byte, error) {
	data := notppkts.SerializeString(nil, p.OID, notppkts.PacketNullByte)
	data = notppkts.SerializeString(data, p.OType, notppkts.PacketNullByte)
	data = notppkts.SerializeBytes(data, p.Content, notppkts.PacketNullByte)
	return data, nil
}

// Deserialize deserializes the packet.
func (p *ObjectStatePacket) Deserialize(data []byte) error {
	var err error
	p.OID, data, err = notppkts.DeserializeString(data, notppkts.PacketNullByte)
	if err != nil {
		return err
	}
	p.OType, data, err = notppkts.DeserializeString(data, notppkts.PacketNullByte)
	if err != nil {
		return err
	}
	p.Content, _, err = notppkts.DeserializeBytes(data, notppkts.PacketNullByte)
	if err != nil {
		return err
	}
	return nil
}
