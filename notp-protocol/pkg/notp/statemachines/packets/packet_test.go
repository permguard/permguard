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

// TestStatePacket tests the state packet.
func TestStatePacket(t *testing.T) {
	assert := assert.New(t)

	stateInput := &StatePacket{
		MessageCode:  111,
		MessageValue: 222,
		ErrorCode:    333,
	}
	data, err := stateInput.Serialize()
	assert.NoError(err)
	assert.Len(data, 15)

	stateOutput := &StatePacket{}
	err = stateOutput.Deserialize(data)
	assert.NoError(err)

	assert.Equal(stateInput.MessageCode, stateOutput.MessageCode)
	assert.Equal(stateInput.MessageValue, stateOutput.MessageValue)
	assert.Equal(stateInput.ErrorCode, stateOutput.ErrorCode)
}
