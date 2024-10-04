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

// AdvertiseObjectRequestStatePacket is the packet to advertise the object request state.
type AdvertiseObjectRequestStatePacket struct {
	// OID is the OID.
	OID 	string
	// OType is the object type.
	OType 	string
}

// GetType returns the type of the packet.
func (p *AdvertiseObjectRequestStatePacket) GetType() uint64 {
	return notppackets.CombineUint32toUint64(AdvertiseObjectRequestStatePacketType, 0)
}

// Serialize serializes the packet.
func (p *AdvertiseObjectRequestStatePacket) Serialize() ([]byte, error) {
	buffer := bytes.NewBuffer([]byte{})

	err := binary.Write(buffer, binary.BigEndian, p.OID)
	if err != nil {
		return nil, fmt.Errorf("failed to write OID: %v", err)
	}

	err = binary.Write(buffer, binary.BigEndian, p.OType)
	if err != nil {
		return nil, fmt.Errorf("failed to write OType: %v", err)
	}

	return buffer.Bytes(), nil
}

// Deserialize deserializes the packet.
func (p *AdvertiseObjectRequestStatePacket) Deserialize(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("buffer too small, need at least 12 bytes but got %d", len(data))
	}

	buffer := bytes.NewBuffer(data)

	err := binary.Read(buffer, binary.BigEndian, &p.OID)
	if err != nil {
		return fmt.Errorf("failed to read StateCode: %v", err)
	}

	err = binary.Read(buffer, binary.BigEndian, &p.OType)
	if err != nil {
		return fmt.Errorf("failed to read StateValue: %v", err)
	}

	return nil
}
