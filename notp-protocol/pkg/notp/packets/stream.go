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

const (
	// uint64Size is the size in bytes of a uint64 value.
	uint64Size = 8
)

// writeStreamDataPacket writes a stream data packet to the buffer.
// Format: [packetStream:8][packetType:8][size:8][payload:size]
func writeStreamDataPacket(data []byte, packetType uint64, packetStream *uint64, payload []byte) ([]byte, error) {
	size := uint64(len(payload))
	values := []uint64{}
	if packetStream != nil {
		values = append(values, *packetStream)
	}
	values = append(values, packetType, size)
	for _, value := range values {
		bufData := make([]byte, uint64Size)
		binary.BigEndian.PutUint64(bufData, value)
		data = append(data, bufData...)
	}
	data = append(data, payload...)
	return data, nil
}

// writeDataPacket writes a data packet to the buffer.
// Format: [packetType:8][size:8][payload:size]
func writeDataPacket(data []byte, packetType uint64, payload []byte) ([]byte, error) {
	return writeStreamDataPacket(data, packetType, nil, payload)
}

// indexDataStreamPacket indexes a stream data packet in the buffer.
// Expects a fixed 24-byte header: [packetStream:8][packetType:8][size:8]
func indexDataStreamPacket(offset int, data []byte) (int, int, uint64, uint64, error) {
	headerSize := uint64Size * 3
	if offset+headerSize > len(data) {
		return -1, -1, 0, 0, errors.New("notp: insufficient data for stream packet header")
	}
	headerData := data[offset : offset+headerSize]
	packetStream := binary.BigEndian.Uint64(headerData[0:uint64Size])
	packetType := binary.BigEndian.Uint64(headerData[uint64Size : uint64Size*2])
	size := int(binary.BigEndian.Uint64(headerData[uint64Size*2 : uint64Size*3]))
	dataOffset := offset + headerSize
	return dataOffset, size, packetType, packetStream, nil
}

// readStreamDataPacket reads a stream data packet from the buffer.
func readStreamDataPacket(offset int, data []byte) ([]byte, int, int, uint64, uint64, error) {
	offset, size, packetType, packetStream, err := indexDataStreamPacket(offset, data)
	if err != nil {
		return nil, -1, -1, 0, 0, err
	}
	if offset+size > len(data) {
		return nil, -1, -1, 0, 0, errors.New("notp: payload size exceeds packet data bounds")
	}
	payload := data[offset : offset+size]
	return payload, offset, size, packetType, packetStream, nil
}

// indexDataPacket indexes a data packet in the buffer.
// Expects a fixed 16-byte header: [packetType:8][size:8]
func indexDataPacket(offset int, data []byte) (int, int, uint64, error) {
	headerSize := uint64Size * 2
	if offset+headerSize > len(data) {
		return -1, -1, 0, errors.New("notp: insufficient data for packet header")
	}
	headerData := data[offset : offset+headerSize]
	packetType := binary.BigEndian.Uint64(headerData[0:uint64Size])
	size := int(binary.BigEndian.Uint64(headerData[uint64Size : uint64Size*2]))
	dataOffset := offset + headerSize
	return dataOffset, size, packetType, nil
}

// readDataPacket reads a data packet from the buffer.
func readDataPacket(offset int, data []byte) ([]byte, int, int, uint64, error) {
	offset, size, packetType, err := indexDataPacket(offset, data)
	if err != nil {
		return nil, -1, -1, 0, err
	}
	if offset+size > len(data) {
		return nil, -1, -1, 0, errors.New("notp: payload size exceeds packet data bounds")
	}
	payload := data[offset : offset+size]
	return payload, offset, size, packetType, nil
}
