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
	"github.com/stretchr/testify/require"
)

// TestRemoteRefStatePacket tests the remote ref state packet
func TestRemoteRefStatePacket(t *testing.T) {
	assert := assert.New(t)

	packet := &RemoteRefStatePacket{}
	packet.OpCode = 0x15
	packet.RefPrevCommit = "477161cc-83c5-4004-8901-a61727ce045a"
	packet.RefCommit = "952dd2f1-1ba2-44b5-92d0-1b6fb8d6f3c0"

	data, err := packet.Serialize()
	require.NoError(t, err)

	newPacket := &RemoteRefStatePacket{}
	err = newPacket.Deserialize(data)

	require.NoError(t, err)
	assert.Equal(packet.RefPrevCommit, newPacket.RefPrevCommit)
	assert.Equal(packet.RefCommit, newPacket.RefCommit)
	assert.Equal(packet.OpCode, newPacket.OpCode)
}
