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
	"errors"
)

// PacketReader is a readr of packets from the NOTP protocol.
type PacketReader struct {
	packet *Packet
}

// NewPacketReader creates a new packet readr.
func NewPacketReader(packet *Packet) (*PacketReader, error) {
	if packet == nil {
		return nil, errors.New("notp: nil packet")
	}
	if packet.Data == nil {
		packet.Data = []byte{}
	}
	return &PacketReader{
		packet: packet,
	}, nil
}

// ReadProtocol read a protocol packet.
func (w *PacketReader) ReadProtocol() (*ProtocolPacket, error) {
	data := w.packet.Data
	if len(data) == 0 {
		return nil, errors.New("notp: missing protocol packet")
	}
	payload, _, _, _, err := readDataPacket(0, data)
	if err != nil {
		return nil, err
	}
	protocol := &ProtocolPacket{}
	err = protocol.Deserialize(payload)
	if err != nil {
		return nil, err
	}
	return protocol, nil
}

// DataPacketState is the state of a data packet.
type DataPacketState struct {
	offeset           int
	size              int
	packetType        uint64
	packetStreamSize  uint64
	packetStreamIndex uint64
}

// GetPacketType returns the type of the data packet.
func (p *DataPacketState) GetPacketType() uint64 {
	return p.packetType
}

// IsComplete returns true if the data packet is complete.
func (p *DataPacketState) IsComplete() bool {
	return p.packetStreamSize-1 == p.packetStreamIndex
}

// ReadNextDataPacket read next data packet.
func (w *PacketReader) ReadNextDataPacket(state *DataPacketState) ([]byte, *DataPacketState, error) {
	if state != nil && state.IsComplete() {
		return nil, state, errors.New("notp: data packet already complete")
	}
	data := w.packet.Data
	if len(data) == 0 {
		return nil, state, errors.New("notp: missing protocol packet")
	}
	if state == nil {
		offset, size, _, err := indexDataPacket(0, data)
		if err != nil {
			return nil, state, err
		}
		data, offset, size, packetType, packetStreamSize, err := readStreamDataPacket(offset+size, data)
		if err != nil {
			return nil, state, err
		}
		state = &DataPacketState{
			offeset:           offset,
			size:              size,
			packetType:        packetType,
			packetStreamSize:  packetStreamSize,
			packetStreamIndex: uint64(0),
		}
		return DecodeByteArray(data), state, nil
	}
	offset := state.offeset + state.size
	payload, offset, size, packetType, err := readDataPacket(offset, data)
	if err != nil {
		return nil, state, err
	}
	state.offeset = offset
	state.packetType = packetType
	state.size = size
	state.packetStreamIndex++
	return DecodeByteArray(payload), state, nil
}
