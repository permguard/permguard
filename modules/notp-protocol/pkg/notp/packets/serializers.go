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
	"math"
)

// SplitData splits the data.
func SplitData[T any](data []byte, nullByte byte, expectedSize int) ([]byte, []byte, error) {
	index := bytes.IndexByte(data, nullByte)
	if index == -1 {
		return nil, nil, fmt.Errorf("missing null byte")
	}
	currentData := data[:index]
	leftData := data[index+1:]
	size := len(currentData)
	if (size == 0 && expectedSize != 0) || len(currentData) > expectedSize {
		return nil, nil, fmt.Errorf("invalid data: missing or invalid data")
	}
	return currentData, leftData, nil
}

// SerializeString serializes a string.
func SerializeString(data []byte, value string, nullByte byte) []byte {
	if data == nil {
		data = make([]byte, 0)
	}
	data = append(data, EncodeByteArray([]byte(value))...)
	return append(data, nullByte)
}

// DeserializeString deserializes a string.
func DeserializeString(data []byte, nullByte byte) (string, []byte, error) {
	currentBuffer, leftBuffer, err := SplitData[string](data, PacketNullByte, math.MaxInt64)
	if err != nil {
		return "", nil, fmt.Errorf("missing data for string")
	}
	return string(DecodeByteArray(currentBuffer)), leftBuffer, nil
}

// SerializeBytes serializes bytes.
func SerializeBytes(data []byte, value []byte, nullByte byte) []byte {
	if data == nil {
		data = make([]byte, 0)
	}
	data = append(data, EncodeByteArray(value)...)
	return append(data, nullByte)
}

// DeserializeBytes deserializes a bytes.
func DeserializeBytes(data []byte, nullByte byte) ([]byte, []byte, error) {
	currentBuffer, leftBuffer, err := SplitData[[]byte](data, PacketNullByte, math.MaxInt64)
	if err != nil {
		return nil, nil, fmt.Errorf("missing data for bytes")
	}
	return DecodeByteArray(currentBuffer), leftBuffer, nil
}

// SerializeBool serializes a bool.
func SerializeBool(data []byte, value bool, nullByte byte) []byte {
	if data == nil {
		data = make([]byte, 0)
	}
	var input byte
	if value {
		input = 1
	} else {
		input = 0
	}
	data = append(data, input)
	return append(data, nullByte)
}

// DeserializeBool deserializes a bool.
func DeserializeBool(data []byte, nullByte byte) (bool, []byte, error) {
	currentBuffer, leftBuffer, err := SplitData[bool](data, PacketNullByte, 1)
	if len(currentBuffer) != 1 {
		return false, nil, fmt.Errorf("missing data for bool")
	}
	if err != nil {
		return false, nil, fmt.Errorf("missing data for bool")
	}
	return currentBuffer[0] == 1, leftBuffer, nil
}

// SerializeUint16 serializes a uint16.
func SerializeUint16(data []byte, value uint16, nullByte byte) []byte {
	if data == nil {
		data = make([]byte, 0)
	}
	input := make([]byte, 2)
	binary.BigEndian.PutUint16(input, value)

	data = append(data, input...)
	return append(data, nullByte)
}

// DeserializeUint16 deserializes a uint16.
func DeserializeUint16(data []byte, nullByte byte) (uint16, []byte, error) {
	currentBuffer, leftBuffer, err := SplitData[bool](data, PacketNullByte, 2)
	if len(currentBuffer) != 2 {
		return 0, nil, fmt.Errorf("missing data for uint16")
	}
	if err != nil {
		return 0, nil, fmt.Errorf("missing data for uint16")
	}
	return binary.BigEndian.Uint16(currentBuffer), leftBuffer, nil
}

// SerializeUint32 serializes a uint32.
func SerializeUint32(data []byte, value uint32, nullByte byte) []byte {
	if data == nil {
		data = make([]byte, 0)
	}
	input := make([]byte, 4)
	binary.BigEndian.PutUint32(input, value)

	data = append(data, input...)
	return append(data, nullByte)
}

// DeserializeUint32 deserializes a uint32.
func DeserializeUint32(data []byte, nullByte byte) (uint32, []byte, error) {
	currentBuffer, leftBuffer, err := SplitData[bool](data, PacketNullByte, 4)
	if len(currentBuffer) != 4 {
		return 0, nil, fmt.Errorf("missing data for uint32")
	}
	if err != nil {
		return 0, nil, fmt.Errorf("missing data for uint32")
	}
	return binary.BigEndian.Uint32(currentBuffer), leftBuffer, nil
}

// SerializeUint64 serializes a uint64.
func SerializeUint64(data []byte, value uint64, nullByte byte) []byte {
	if data == nil {
		data = make([]byte, 0)
	}
	input := make([]byte, 8)
	binary.BigEndian.PutUint64(input, value)

	data = append(data, input...)
	return append(data, nullByte)
}

// DeserializeUint64 deserializes a uint64.
func DeserializeUint64(data []byte, nullByte byte) (uint64, []byte, error) {
	currentBuffer, leftBuffer, err := SplitData[bool](data, PacketNullByte, 8)
	if len(currentBuffer) != 8 {
		return 0, nil, fmt.Errorf("missing data for uint64")
	}
	if err != nil {
		return 0, nil, fmt.Errorf("missing data for uint64")
	}
	return binary.BigEndian.Uint64(currentBuffer), leftBuffer, nil
}
