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

// SamplePacket represents a sample packet.
type SamplePacket struct {
	Text string
}

// Type returns the type of the packet.
func (p *SamplePacket) Type() uint64 {
	return 0
}

// Serialize serializes the packet.
func (p *SamplePacket) Serialize() ([]byte, error) {
	data := SerializeString(nil, p.Text, PacketNullByte)
	return data, nil
}

// Deserialize deserializes the packet.
func (p *SamplePacket) Deserialize(data []byte) error {
	var err error
	p.Text, _, err = DeserializeString(data, PacketNullByte)
	if err != nil {
		return err
	}
	return nil
}

func TestPacketWriterAndReader(t *testing.T) {
	assert := assert.New(t)

	// Create a new in-memory packet container
	packet := &Packet{}

	// Initialize a writer for the packet
	writer, err := NewPacketWriter(packet)
	assert.Nil(err)

	// Write the protocol header
	inProtocol := &ProtocolPacket{Version: 10}
	err = writer.WriteProtocol(inProtocol)
	assert.Nil(err)

	// Append three sample data packets to the stream
	inData1 := &SamplePacket{Text: "fd1d3938-2988-4df3-9b83-cc278b69cab0"}
	err = writer.AppendDataPacket(inData1)
	assert.Nil(err)

	inData2 := &SamplePacket{Text: "3ecd7285-8406-4647-8e8f-92d87348636d"}
	err = writer.AppendDataPacket(inData2)
	assert.Nil(err)

	inData3 := &SamplePacket{Text: "83ce2f5b-f5c4-4bd7-85de-69291f1f80d4"}
	err = writer.AppendDataPacket(inData3)
	assert.Nil(err)

	// Initialize a reader for the same packet
	reader, err := NewPacketReader(packet)
	assert.Nil(err)

	// Read and verify the protocol header
	outProtocol, err := reader.ReadProtocol()
	assert.Nil(err)
	assert.Equal(inProtocol.Version, outProtocol.Version)

	// --- Read first data packet ---
	data, state, err := reader.ReadNextDataPacket(nil)
	assert.Nil(err)
	assert.NotNil(state)
	assert.Equal(state.packetType, inData1.Type())
	assert.Equal(state.packetStreamSize, uint64(3))
	assert.Equal(state.packetStreamIndex, uint64(0))

	outData1 := &SamplePacket{}
	err = outData1.Deserialize(data)
	assert.Nil(err)
	assert.False(state.IsComplete())
	assert.Equal(inData1.Text, outData1.Text)

	// --- Read second data packet ---
	data, state, err = reader.ReadNextDataPacket(state)
	assert.Nil(err)
	assert.Equal(state.packetType, inData2.Type())
	assert.Equal(state.packetStreamSize, uint64(3))
	assert.Equal(state.packetStreamIndex, uint64(1))

	outData2 := &SamplePacket{}
	err = outData2.Deserialize(data)
	assert.Nil(err)
	assert.False(state.IsComplete())
	assert.Equal(inData2.Text, outData2.Text)

	// --- Read third data packet ---
	data, state, err = reader.ReadNextDataPacket(state)
	assert.Nil(err)
	assert.Equal(state.packetType, inData2.Type()) // still same type
	assert.Equal(state.packetStreamSize, uint64(3))
	assert.Equal(state.packetStreamIndex, uint64(2))

	outData3 := &SamplePacket{}
	err = outData3.Deserialize(data)
	assert.Nil(err)
	assert.True(state.IsComplete())
	assert.Equal(inData3.Text, outData3.Text)

	// --- Attempt to read past end of stream ---
	data, state, err = reader.ReadNextDataPacket(state)
	assert.Nil(data)
	assert.NotNil(state)
	assert.NotNil(err)
}
