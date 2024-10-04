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

// ObjectStatePacket is the packet to advertise the object state.
type ObjectStatePacket struct {
	// Content represents the object's content.
	Content []byte
}

// Serialize serializes the packet.
func (p *ObjectStatePacket) Serialize() ([]byte, error) {
	buffer := bytes.NewBuffer([]byte{})

	err := binary.Write(buffer, binary.BigEndian, notppackets.EncodeByteArray(p.Content))
	if err != nil {
		return nil, fmt.Errorf("failed to write Content: %v", err)
	}

	return buffer.Bytes(), nil
}

// Deserialize deserializes the packet.
func (p *ObjectStatePacket) Deserialize(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("buffer too small, need at least one byte")
	}

	p.Content = notppackets.DecodeByteArray(data)

	return nil
}
