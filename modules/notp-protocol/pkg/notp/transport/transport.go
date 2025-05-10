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

// Package transport implements the transport layer of the NOTP protocol.
package transport

import (
	"errors"

	azdata "github.com/permguard/permguard/common/pkg/extensions/data"
	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
)

// TransportLayer represents the transport layer responsible for packet transmission in the NOTP protocol.
type TransportLayer struct {
	inspector      *PacketInspector
	packetSender   PacketSender
	packetReceiver PacketReceiver
}

// TransmitPacket sends a packet through the transport layer.
func (t *TransportLayer) TransmitPacket(packetables []notppackets.Packetable) error {
	if t.packetSender == nil {
		return errors.New("notp: transport layer does not have a defined packet sender")
	}
	if len(packetables) == 0 {
		return errors.New("notp: cannot send an empty packet")
	}
	packet := notppackets.Packet{}
	writer, err := notppackets.NewPacketWriter(&packet)
	if err != nil {
		return err
	}
	writer.WriteProtocol(&notppackets.ProtocolPacket{Version: 1})
	for _, packetable := range packetables {
		err := writer.AppendDataPacket(packetable)
		if err != nil {
			return err
		}
	}
	compressedData, err := azdata.CompressData(packet.Data)
	if err != nil {
		return err
	}
	packet.Data = compressedData
	err = t.packetSender(&packet)
	if err != nil {
		return err
	}
	if t.inspector != nil {
		t.inspector.InspectSent(&packet)
	}
	return nil
}

// ReceivePacket retrieves a packet from the transport layer.
func (t *TransportLayer) ReceivePacket() ([]notppackets.Packetable, error) {
	if t.packetReceiver == nil {
		return nil, errors.New("notp: transport layer does not have a defined packet receiver")
	}
	packet, err := t.packetReceiver()
	if err != nil {
		return nil, err
	}
	if packet == nil {
		return nil, errors.New("notp: received a nil packet")
	}
	decompressedData, err := azdata.DecompressData(packet.Data)
	if err != nil {
		return nil, err
	}
	packet.Data = decompressedData
	if t.inspector != nil {
		t.inspector.InspectReceived(packet)
	}
	reader, err := notppackets.NewPacketReader(packet)
	if err != nil {
		return nil, err
	}
	protocol, err := reader.ReadProtocol()
	if err != nil {
		return nil, err
	}
	if protocol.Version != 1 {
		return nil, errors.New("notp: unsupported protocol version")
	}
	packetables := []notppackets.Packetable{}
	var state *notppackets.DataPacketState
	for {
		var data []byte
		data, state, err = reader.ReadNextDataPacket(state)
		if err != nil {
			return nil, err
		}
		packetable := &notppackets.Packet{
			Data: data,
		}
		packetables = append(packetables, packetable)
		if state.IsComplete() {
			break
		}
	}
	return packetables, nil
}

// NewTransportLayer creates and initializes a new transport layer.
func NewTransportLayer(packetSender PacketSender, packetReceiver PacketReceiver, inspector *PacketInspector) (*TransportLayer, error) {
	if packetSender == nil {
		return nil, errors.New("notp: PacketSender cannot be nil")
	}
	if packetReceiver == nil {
		return nil, errors.New("notp: PacketReceiver cannot be nil")
	}
	return &TransportLayer{
		inspector:      inspector,
		packetSender:   packetSender,
		packetReceiver: packetReceiver,
	}, nil
}
