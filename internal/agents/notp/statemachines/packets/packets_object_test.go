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

// TestObjectStatePacket tests the object state packet
func TestObjectStatePacket(t *testing.T) {
	assert := assert.New(t)

	packet := &ObjectStatePacket{}
	packet.OID = "41d8c67c-705f-4d7e-a758-46e86d0fd9e6"
	packet.OType = "mycustomtype"
	packet.Content = []byte("mycontent")

	data, err := packet.Serialize()
	assert.Nil(err)

	newPacket := &ObjectStatePacket{}
	err = newPacket.Deserialize(data)

	assert.Nil(err)
	assert.Equal(packet.OID, newPacket.OID)
	assert.Equal(packet.OType, newPacket.OType)
	assert.Equal(packet.Content, packet.Content)
}
