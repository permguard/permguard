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

	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
)

// ObjectRequestStatePacket is the packet to  the object request state.
type ObjectRequestStatePacket struct {
	// OID is the OID.
	OID 	string
	// OType is the object type.
	OType 	string
	// Content represents the object's content.
	Content []byte
}

// Serialize serializes the packet.
func (p *ObjectRequestStatePacket) Serialize() ([]byte, error) {
	buffer := bytes.NewBuffer([]byte{})

	err := binary.Write(buffer, binary.BigEndian, notppackets.EncodeByteArray([]byte(p.OID)))
	if err != nil {
		return nil, fmt.Errorf("failed to write OID: %v", err)
	}

	err = buffer.WriteByte(notppackets.PacketNullByte)
	if err != nil {
		return nil, fmt.Errorf("failed to write null byte after OID: %v", err)
	}

	err = binary.Write(buffer, binary.BigEndian, notppackets.EncodeByteArray([]byte(p.OType)))
	if err != nil {
		return nil, fmt.Errorf("failed to write OType: %v", err)
	}

	err = buffer.WriteByte(notppackets.PacketNullByte)
	if err != nil {
		return nil, fmt.Errorf("failed to write null byte after OType: %v", err)
	}

	err = binary.Write(buffer, binary.BigEndian, notppackets.EncodeByteArray(p.Content))
	if err != nil {
		return nil, fmt.Errorf("failed to write Content: %v", err)
	}

	return buffer.Bytes(), nil
}

// Deserialize deserializes the packet.
func (p *ObjectRequestStatePacket) Deserialize(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too small, need at least one byte")
	}

	oidNullByteIndex := bytes.IndexByte(data, notppackets.PacketNullByte)
	if oidNullByteIndex == -1 {
		return fmt.Errorf("missing first null byte")
	}
	p.OID = string(notppackets.DecodeByteArray(data[:oidNullByteIndex]))
	if oidNullByteIndex+1 >= len(data) {
		return fmt.Errorf("missing data after OID")
	}

	startIndex := oidNullByteIndex + 1
	otypeNullByteIndex := bytes.IndexByte(data[startIndex:], notppackets.PacketNullByte)
	if otypeNullByteIndex == -1 {
		return fmt.Errorf("missing second null byte")
	}
	otypeNullByteIndex += startIndex
	p.OType = string(notppackets.DecodeByteArray(data[startIndex:otypeNullByteIndex]))
	if otypeNullByteIndex+1 > len(data) {
		return fmt.Errorf("missing data after OType")
	}

	startIndex = otypeNullByteIndex + 1
	p.Content = notppackets.DecodeByteArray(data[startIndex:])

	return nil
}
