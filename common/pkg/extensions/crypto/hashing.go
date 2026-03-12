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

package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// ComputeSHA256 computes the SHA256 hash of the given data.
// It returns the hash as a lowercase hexadecimal string.
// This function is safe for concurrent use.
func ComputeSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ComputeStringSHA256 computes the SHA256 hash of the given string.
// It converts the string to bytes and delegates to ComputeSHA256.
// This function is safe for concurrent use.
func ComputeStringSHA256(data string) string {
	return ComputeSHA256([]byte(data))
}

// ComputeCID computes a CIDv1 content identifier for the given data.
// It uses SHA2-256 as the hash function and dag-cbor as the codec.
// The returned string is the base32-encoded CID.
// This function is safe for concurrent use.
func ComputeCID(data []byte) (string, error) {
	hash, err := mh.Sum(data, mh.SHA2_256, -1)
	if err != nil {
		return "", fmt.Errorf("crypto: failed to compute multihash: %w", err)
	}
	c := cid.NewCidV1(cid.DagCBOR, hash)
	return c.String(), nil
}

// ComputeStringCID computes a CIDv1 content identifier for the given string.
// It converts the string to bytes and delegates to ComputeCID.
// This function is safe for concurrent use.
func ComputeStringCID(data string) (string, error) {
	return ComputeCID([]byte(data))
}

// VerifyCID verifies that the content matches the expected CID.
// It parses the CID to extract the hash algorithm and codec, then recomputes
// the CID from the content and compares it with the expected value.
func VerifyCID(expectedCID string, content []byte) error {
	expected, err := cid.Decode(expectedCID)
	if err != nil {
		return fmt.Errorf("crypto: failed to decode CID: %w", err)
	}
	hash, err := mh.Sum(content, expected.Prefix().MhType, -1)
	if err != nil {
		return fmt.Errorf("crypto: failed to compute multihash: %w", err)
	}
	computed := cid.NewCidV1(expected.Prefix().Codec, hash)
	if !expected.Equals(computed) {
		return fmt.Errorf("crypto: CID mismatch: expected %s, computed %s", expectedCID, computed.String())
	}
	return nil
}

// ZeroCID is a CIDv1 with dag-cbor codec and an all-zero SHA2-256 digest.
// It is used as a sentinel value representing the absence of content.
var ZeroCID string

func init() {
	zeroDigest := make([]byte, 32)
	encoded, _ := mh.Encode(zeroDigest, mh.SHA2_256)
	c := cid.NewCidV1(cid.DagCBOR, encoded)
	ZeroCID = c.String()
}
