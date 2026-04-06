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
	"errors"
	"fmt"
)

// cborBlob is the CBOR-serializable representation of a blob object.
type cborBlob struct {
	DataType uint32         `cbor:"1,keyasint"`
	Metadata map[string]any `cbor:"2,keyasint"`
	Data     []byte         `cbor:"3,keyasint"`
}

// SerializeBlob serializes an ObjectHeader and its associated data into CBOR.
func (m *ObjectManager) SerializeBlob(header *ObjectHeader, data []byte) ([]byte, error) {
	if header == nil {
		return nil, errors.New("objects: header is nil")
	}
	b := cborBlob{
		DataType: header.dataType,
		Metadata: header.metadata,
		Data:     data,
	}
	return m.encMode.Marshal(b)
}

// DeserializeBlob deserializes an ObjectHeader and its associated data from CBOR.
func (m *ObjectManager) DeserializeBlob(data []byte) (*ObjectHeader, []byte, error) {
	if len(data) == 0 {
		return nil, nil, errors.New("objects: data is empty")
	}
	var b cborBlob
	if err := m.decMode.Unmarshal(data, &b); err != nil {
		return nil, nil, fmt.Errorf("objects: failed to decode blob: %w", err)
	}
	header := &ObjectHeader{
		dataType: b.DataType,
		metadata: b.Metadata,
	}
	return header, b.Data, nil
}
