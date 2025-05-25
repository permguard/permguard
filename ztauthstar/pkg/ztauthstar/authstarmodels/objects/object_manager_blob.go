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

package objects

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

// SerializeBlob serializes an ObjectHeader and its associated data into a binary format.
// The serialization format starts with Partition and includes a null byte delimiter
// between the header and the blob content.
func (m *ObjectManager) SerializeBlob(header *ObjectHeader, data []byte) ([]byte, error) {
	if header == nil {
		return nil, errors.New("objects: header is nil")
	}

	var buffer bytes.Buffer

	// Write Partition as string prefixed with uint16 length
	partitionBytes := []byte(header.partition)
	partitionLen := uint16(len(partitionBytes))
	if err := binary.Write(&buffer, binary.BigEndian, partitionLen); err != nil {
		return nil, err
	}
	if _, err := buffer.Write(partitionBytes); err != nil {
		return nil, err
	}

	// Write standard header fields
	if err := binary.Write(&buffer, binary.BigEndian, header.isNativeLanguage); err != nil {
		return nil, err
	}
	if err := binary.Write(&buffer, binary.BigEndian, header.languageID); err != nil {
		return nil, err
	}
	if err := binary.Write(&buffer, binary.BigEndian, header.languageVersionID); err != nil {
		return nil, err
	}
	if err := binary.Write(&buffer, binary.BigEndian, header.languageTypeID); err != nil {
		return nil, err
	}
	if err := binary.Write(&buffer, binary.BigEndian, header.codeTypeID); err != nil {
		return nil, err
	}

	// Encode codeID as base64 string with length prefix
	encodedCodeID := base64.StdEncoding.EncodeToString([]byte(header.codeID))
	codeIDBytes := []byte(encodedCodeID)
	codeIDLen := uint16(len(codeIDBytes))
	if err := binary.Write(&buffer, binary.BigEndian, codeIDLen); err != nil {
		return nil, err
	}
	if _, err := buffer.Write(codeIDBytes); err != nil {
		return nil, err
	}

	// Write null byte as header delimiter
	if err := buffer.WriteByte(PacketNullByte); err != nil {
		return nil, err
	}

	// Append actual blob content
	return append(buffer.Bytes(), data...), nil
}

// DeserializeBlob deserializes an ObjectHeader and its associated data from a binary format.
// The header is expected to end with a null byte delimiter, followed by the content data.
func (m *ObjectManager) DeserializeBlob(data []byte) (*ObjectHeader, []byte, error) {
	if len(data) < 1 {
		return nil, nil, errors.New("objects: data is too short to contain an ObjectHeader")
	}

	delimiterIndex := bytes.IndexByte(data, PacketNullByte)
	if delimiterIndex == -1 {
		return nil, nil, errors.New("objects: null packet delimiter not found")
	}

	reader := bytes.NewReader(data[:delimiterIndex])
	header := &ObjectHeader{}

	// Read Partition string (uint16 length + bytes)
	var partitionLen uint16
	if err := binary.Read(reader, binary.BigEndian, &partitionLen); err != nil {
		return nil, nil, errors.New("objects: failed to read partition length")
	}
	partitionBytes := make([]byte, partitionLen)
	if _, err := reader.Read(partitionBytes); err != nil {
		return nil, nil, errors.New("objects: failed to read partition")
	}
	header.partition = string(partitionBytes)

	// Read standard header fields
	if err := binary.Read(reader, binary.BigEndian, &header.isNativeLanguage); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &header.languageID); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &header.languageVersionID); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &header.languageTypeID); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(reader, binary.BigEndian, &header.codeTypeID); err != nil {
		return nil, nil, err
	}

	// Read and decode codeID from base64-encoded string
	var codeIDLen uint16
	if err := binary.Read(reader, binary.BigEndian, &codeIDLen); err != nil {
		return nil, nil, errors.New("objects: failed to read codeID length")
	}
	codeIDBytes := make([]byte, codeIDLen)
	if _, err := reader.Read(codeIDBytes); err != nil {
		return nil, nil, errors.New("objects: failed to read codeID")
	}
	decodedCodeID, err := base64.StdEncoding.DecodeString(string(codeIDBytes))
	if err != nil {
		return nil, nil, errors.New("objects: failed to decode codeID")
	}
	header.codeID = string(decodedCodeID)

	// Extract remaining data after null byte
	remainingData := data[delimiterIndex+1:]
	return header, remainingData, nil
}
