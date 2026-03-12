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
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// SerializeCBOR serializes a value to CBOR bytes.
func SerializeCBOR(v any) ([]byte, error) {
	data, err := cbor.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("notp: failed to serialize CBOR: %w", err)
	}
	return data, nil
}

// DeserializeCBOR deserializes CBOR bytes into a value.
func DeserializeCBOR(data []byte, v any) error {
	if err := cbor.Unmarshal(data, v); err != nil {
		return fmt.Errorf("notp: failed to deserialize CBOR: %w", err)
	}
	return nil
}
