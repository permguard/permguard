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

package data

import (
	"bytes"
	"compress/zlib"
)

// CompressData compresses data.
func CompressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zlibWriter := zlib.NewWriter(&buf)
	if _, err := zlibWriter.Write(data); err != nil {
		return nil, err
	}
	if err := zlibWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecompressData decompresses data.
func DecompressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(data)
	zlibReader, err := zlib.NewReader(&buf)
	if err != nil {
		return nil, err
	}
	defer zlibReader.Close()

	var outBuf bytes.Buffer
	if _, err := outBuf.ReadFrom(zlibReader); err != nil {
		return nil, err
	}
	return outBuf.Bytes(), nil
}
