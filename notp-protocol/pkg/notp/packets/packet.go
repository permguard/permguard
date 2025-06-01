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

import "fmt"

const (
	// ProtocolPacketType represents the type of the generic packet.
	PacketType = uint32(0)
	// ProtocolPacketType represents the type of the protocol packet.
	ProtocolPacketType = uint32(1)
)

// Packet represents a packet.
type Packet struct {
	Data []byte
}

// Type returns the packet type.
func (p *Packet) Type() uint64 {
	return CombineUint32toUint64(PacketType, 0)
}

// Serialize serializes the packet.
func (p *Packet) Serialize() ([]byte, error) {
	return p.Data, nil
}

// Deserialize deserializes the packet.
func (p *Packet) Deserialize(data []byte) error {
	p.Data = data
	return nil
}

// Packetable represents a packet that can be serialized and deserialized.
type Packetable interface {
	Type() uint64
	Serialize() ([]byte, error)
	Deserialize([]byte) error
}

// ConvertPacketable converts a packetable to a new instance of the input type.
func ConvertPacketable(packet Packetable, target Packetable) error {
	data, err := packet.Serialize()
	if err != nil {
		return fmt.Errorf("notp: failed to serialize packet: %w", err)
	}
	err = target.Deserialize(data)
	if err != nil {
		return fmt.Errorf("notp: failed to deserialize packet: %w", err)
	}
	return nil
}

// CombineUint32toUint64 combines two uint32 into a uint64.
func CombineUint32toUint64(high, low uint32) uint64 {
	return (uint64(high) << 32) | uint64(low)
}

// SplitUint64toUint32 splits a uint64 into two uint32.
func SplitUint64toUint32(value uint64) (uint32, uint32) {
	high := uint32(value >> 32)
	low := uint32(value & 0xFFFFFFFF)
	return high, low
}

// HasUint64AUint32 return
func HasUint64AUint32(value uint64, target uint32) bool {
	high, low := SplitUint64toUint32(value)
	return high == target || low == target
}
