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

// ObjectHeaderStatePacket is object state description packet.
type ObjectHeaderStatePacket struct {
	// OID is the OID.
	OID string
	// OType is the object type.
	OType string
}

// Serialize serializes the packet.
func (p *ObjectHeaderStatePacket) Serialize() ([]byte, error) {
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

	return buffer.Bytes(), nil
}

// Deserialize deserializes the packet.
func (p *ObjectHeaderStatePacket) Deserialize(data []byte) error {
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
	p.OType = string(notppackets.DecodeByteArray(data[startIndex:]))

	return nil
}
