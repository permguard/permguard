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
	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
)

// AdvertiseObjectResponseStatePacket is the packet to advertise the object response state.
type AdvertiseObjectResponseStatePacket struct {
	// Commit is the commit.
	Commit string
}

// GetType returns the type of the packet.
func (p *AdvertiseObjectResponseStatePacket) GetType() uint64 {
	return notppackets.CombineUint32toUint64(AdvertiseObjectResponseStatePacketType, 0)
}

// Serialize serializes the packet.
func (p *AdvertiseObjectResponseStatePacket) Serialize() ([]byte, error) {
	return []byte(p.Commit), nil
}

// Deserialize deserializes the packet.
func (p *AdvertiseObjectResponseStatePacket) Deserialize(data []byte) error {
	p.Commit = string(data)
	return nil
}
