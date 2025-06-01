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

// ProtocolPacket represents a protocol packet.
type ProtocolPacket struct {
	Version uint32
}

// Type returns the type of the packet.
func (p *ProtocolPacket) Type() uint64 {
	return CombineUint32toUint64(ProtocolPacketType, 0)
}

// Serialize serializes the packet.
func (p *ProtocolPacket) Serialize() ([]byte, error) {
	data := SerializeUint32(nil, p.Version, PacketNullByte)
	return data, nil

}

// Deserialize deserializes the packet.
func (p *ProtocolPacket) Deserialize(data []byte) error {
	var err error
	p.Version, _, err = DeserializeUint32(data, PacketNullByte)
	if err != nil {
		return err
	}
	return nil
}
