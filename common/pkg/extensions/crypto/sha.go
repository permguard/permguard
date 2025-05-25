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
)

// ComputeSHA256 computes the SHA1 hash of the given data.
func ComputeSHA256(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	hashBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

// ComputeStringSHA256 computes the SHA1 hash of the given string.
func ComputeStringSHA256(data string) string {
	return ComputeSHA256([]byte(data))
}
