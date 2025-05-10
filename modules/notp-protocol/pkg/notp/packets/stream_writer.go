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
	"encoding/binary"
	"errors"
)

// PacketWriter is a writer of packets from the NOTP protocol.
type PacketWriter struct {
	packet           *Packet
	protocolEndIndex int
	streamEndIndex   int
}

// NewPacketWriter creates a new packet writer.
func NewPacketWriter(packet *Packet) (*PacketWriter, error) {
	if packet == nil {
		return nil, errors.New("notp: nil packet")
	}
	if packet.Data == nil {
		packet.Data = []byte{}
	}
	return &PacketWriter{
		packet:           packet,
		protocolEndIndex: -1,
		streamEndIndex:   -1,
	}, nil
}

// WriteProtocol write a protocol packet.
func (w *PacketWriter) WriteProtocol(protocol *ProtocolPacket) error {
	if protocol == nil {
		return errors.New("notp: nil protocol packet")
	}
	if w.protocolEndIndex > -1 || len(w.packet.Data) > 0 {
		return errors.New("notp: protocol packet already written")
	}
	data, err := protocol.Serialize()
	if err != nil {
		return err
	}
	if w.packet.Data, err = writeDataPacket(w.packet.Data, protocol.GetType(), data); err != nil {
		return err
	}
	w.protocolEndIndex = len(w.packet.Data) - 1
	return nil
}

// AppendDataPacket appends a data packet.
func (w *PacketWriter) AppendDataPacket(packet Packetable) error {
	if packet == nil {
		return errors.New("notp: nil data packet")
	}
	if w.protocolEndIndex == -1 || len(w.packet.Data) == 0 {
		return errors.New("notp: missing protocol packet")
	}
	dataType := packet.GetType()
	data, err := packet.Serialize()
	data = EncodeByteArray(data)
	if err != nil {
		return err
	}
	if w.streamEndIndex == -1 {
		streamSize := uint64(1)
		if w.packet.Data, err = writeStreamDataPacket(w.packet.Data, dataType, &streamSize, data); err != nil {
			return err
		}
	} else {
		if w.packet.Data, err = writeDataPacket(w.packet.Data, dataType, data); err != nil {
			return err
		}
		start := w.protocolEndIndex + 1
		_, _, _, packetStream, _ := indexDataStreamPacket(start, w.packet.Data)
		packetStream++
		binary.BigEndian.PutUint64(w.packet.Data[start:], packetStream)
	}
	w.streamEndIndex = len(w.packet.Data) - 1
	return nil
}
