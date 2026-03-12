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
	"fmt"

	"github.com/permguard/permguard/common/pkg/extensions/crypto"
)

const (
	// DefaultMaxObjectSize is the default maximum object size in bytes (5 MB).
	DefaultMaxObjectSize = 5 * 1024 * 1024
	// DefaultMaxTreeEntries is the default maximum number of entries in a tree object.
	DefaultMaxTreeEntries = 10000
	// DefaultMaxCBORNestedLevels is the default maximum CBOR nesting depth.
	DefaultMaxCBORNestedLevels = 32
	// DefaultMaxObjectsPerTransfer is the default maximum number of objects per single transfer request.
	DefaultMaxObjectsPerTransfer = 10000
	// DefaultMaxTransferSize is the default maximum total transfer size in bytes per request (50 MB).
	DefaultMaxTransferSize = 50 * 1024 * 1024
)

// VerifyOID verifies that the content matches the expected OID.
// It supports CID-based verification by parsing the hash algorithm from the CID itself.
func VerifyOID(expectedOID string, content []byte) error {
	return crypto.VerifyCID(expectedOID, content)
}

// ValidateObjectSize validates the object size against the given limit.
func ValidateObjectSize(content []byte, maxSize int64) error {
	if maxSize <= 0 {
		maxSize = DefaultMaxObjectSize
	}
	if int64(len(content)) > maxSize {
		return fmt.Errorf("objects: object size %d exceeds maximum allowed size %d", len(content), maxSize)
	}
	return nil
}

// ValidateTransferLimits validates the transfer request against rate limits.
func ValidateTransferLimits(objectCount int, totalSize int64, maxObjects int, maxSize int64) error {
	if maxObjects <= 0 {
		maxObjects = DefaultMaxObjectsPerTransfer
	}
	if maxSize <= 0 {
		maxSize = DefaultMaxTransferSize
	}
	if objectCount > maxObjects {
		return fmt.Errorf("objects: transfer contains %d objects, exceeds maximum %d", objectCount, maxObjects)
	}
	if totalSize > maxSize {
		return fmt.Errorf("objects: transfer size %d bytes exceeds maximum %d bytes", totalSize, maxSize)
	}
	return nil
}
