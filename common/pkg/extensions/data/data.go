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
	"io"
)

// CompressData compresses data using zlib compression.
// It returns the compressed data or an error if compression fails.
func CompressData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	var buf bytes.Buffer
	zlibWriter := zlib.NewWriter(&buf)
	defer zlibWriter.Close() // Ensure writer is closed even on error

	_, err := zlibWriter.Write(data)
	if err != nil {
		return nil, err
	}

	err = zlibWriter.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecompressData decompresses zlib-compressed data.
// It returns the decompressed data or an error if decompression fails.
func DecompressData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	buf := bytes.NewReader(data)
	zlibReader, err := zlib.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer zlibReader.Close()

	var outBuf bytes.Buffer
	_, err = io.Copy(&outBuf, zlibReader)
	if err != nil {
		return nil, err
	}

	return outBuf.Bytes(), nil
}
