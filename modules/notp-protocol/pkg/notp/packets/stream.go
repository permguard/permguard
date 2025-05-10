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
	"encoding/base64"
	"encoding/binary"
	"errors"
	"unsafe"
)

const (
	// PacketNullByte is the null byte used to separate data in the packet.
	PacketNullByte = 0xFF
)

// EncodeByteArray encodes a byte array to a base64 string.
func EncodeByteArray(data []byte) []byte {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write(data)
	encoder.Close()
	return buf.Bytes()
}

// DecodeByteArray decodes a base64 string to a byte array.
func DecodeByteArray(data []byte) []byte {
	var buf bytes.Buffer
	decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data))
	_, err := buf.ReadFrom(decoder)
	if err != nil {
		return data
	}
	return buf.Bytes()
}

// writeStreamDataPacket writes a stream data packet to the buffer.
func writeStreamDataPacket(data []byte, packetType uint64, packetStream *uint64, payload []byte) ([]byte, error) {
	size := uint64(len(payload))
	values := []uint64{}
	if packetStream != nil {
		values = append(values, *packetStream)
	}
	values = append(values, packetType, size)
	idSize := int(unsafe.Sizeof(uint64(0)))
	for _, value := range values {
		bufData := make([]byte, idSize)
		binary.BigEndian.PutUint64(bufData, value)
		data = append(data, bufData...)
	}
	data = append(data, PacketNullByte)
	data = append(data, payload...)
	return data, nil
}

// writeDataPacket writes a data packet to the buffer.
func writeDataPacket(data []byte, packetType uint64, payload []byte) ([]byte, error) {
	return writeStreamDataPacket(data, packetType, nil, payload)
}

// indexDataStreamPacket indexes a stream data packet in the buffer.
func indexDataStreamPacket(offset int, data []byte) (int, int, uint64, uint64, error) {
	data = data[offset:]
	delimiterIndex := bytes.IndexByte(data, PacketNullByte)
	if delimiterIndex == -1 {
		return -1, -1, 0, 0, errors.New("notp: delimiter not found")
	}
	headerData := data[:delimiterIndex]
	idSize := int(unsafe.Sizeof(uint64(0)))
	if len(headerData) != idSize*3 {
		return -1, -1, 0, 0, errors.New("notp: invalid data: missing or invalid header")
	}
	dataOffset := delimiterIndex + 1
	values := []uint64{0, 0, 0}
	for count := range values {
		start := idSize * count
		end := (idSize * count) + idSize
		values[count] = uint64(binary.BigEndian.Uint64(headerData[start:end]))
	}
	packetStream := values[0]
	packetType := values[1]
	size := int(values[2])
	return offset + dataOffset, size, packetType, packetStream, nil
}

// readStreamDataPacket reads a stream data packet from the buffer.
func readStreamDataPacket(offset int, data []byte) ([]byte, int, int, uint64, uint64, error) {
	offset, size, packetType, packetStream, err := indexDataStreamPacket(offset, data)
	if err != nil {
		return nil, -1, -1, 0, 0, err
	}
	payload := data[offset : offset+size]
	return payload, offset, size, packetType, packetStream, nil
}

// indexDataPacket indexes a data packet in the buffer.
func indexDataPacket(offset int, data []byte) (int, int, uint64, error) {
	data = data[offset:]
	delimiterIndex := bytes.IndexByte(data, PacketNullByte)
	if delimiterIndex == -1 {
		return -1, -1, 0, errors.New("notp: delimiter not found")
	}
	headerData := data[:delimiterIndex]
	idSize := int(unsafe.Sizeof(uint64(0)))
	if len(headerData) != idSize*2 {
		return -1, -1, 0, errors.New("notp: invalid data: missing or invalid header")
	}
	dataOffset := delimiterIndex + 1
	values := []uint64{0, 0}
	for count := range values {
		start := idSize * count
		end := (idSize * count) + idSize
		values[count] = uint64(binary.BigEndian.Uint64(headerData[start:end]))
	}
	packetType := values[0]
	size := int(values[1])
	return offset + dataOffset, size, packetType, nil
}

// readDataPacket reads a data packet from the buffer.
func readDataPacket(offset int, data []byte) ([]byte, int, int, uint64, error) {
	offset, size, packetType, err := indexDataPacket(offset, data)
	if err != nil {
		return nil, -1, -1, 0, err
	}
	payload := data[offset : offset+size]
	return payload, offset, size, packetType, nil
}
