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
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLocalRefStatePacket tests the local ref state packet
func TestLocalRefStatePacket(t *testing.T) {
	assert := assert.New(t)

	packet := &LocalRefStatePacket{}
	packet.RefCommit = "477161cc-83c5-4004-8901-a61727ce045a"
	packet.HasConflicts = true
	packet.IsUpToDate = true
	packet.NumberOfCommits = 10
	packet.OpCode = 0x15

	data, err := packet.Serialize()
	assert.Nil(err)

	newPacket := &LocalRefStatePacket{}
	err = newPacket.Deserialize(data)

	assert.Nil(err)
	assert.Equal(packet.RefCommit, newPacket.RefCommit)
	assert.Equal(packet.HasConflicts, newPacket.HasConflicts)
	assert.Equal(packet.IsUpToDate, newPacket.IsUpToDate)
	assert.Equal(packet.NumberOfCommits, newPacket.NumberOfCommits)
	assert.Equal(packet.OpCode, newPacket.OpCode)
}
