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

	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
)

// PacketHandler defines a function type for handling packets.
type PacketHandler func(packet *notppackets.Packet)

// PacketSender defines a function type for sending packets over the transport layer.
type PacketSender func(packet *notppackets.Packet) error

// PacketReceiver defines a function type for receiving packets from the transport layer.
type PacketReceiver func() (*notppackets.Packet, error)

// PacketInspector provides functionality to inspect sent and received packets using the provided handlers.
type PacketInspector struct {
	sentPacketHandler     PacketHandler
	receivedPacketHandler PacketHandler
}

// InspectSent calls the handler to process the sent packet.
func (p *PacketInspector) InspectSent(packet *notppackets.Packet) {
	if p.sentPacketHandler != nil {
		p.sentPacketHandler(packet)
	}
}

// InspectReceived calls the handler to process the received packet.
func (p *PacketInspector) InspectReceived(packet *notppackets.Packet) {
	if p.receivedPacketHandler != nil {
		p.receivedPacketHandler(packet)
	}
}

// NewPacketInspector creates and initializes a new PacketInspector with handlers for sent and received packets.
func NewPacketInspector(onSent PacketHandler, onReceived PacketHandler) (*PacketInspector, error) {
	if onSent == nil && onReceived == nil {
		return nil, errors.New("both sent and received packet handlers cannot be nil")
	}

	return &PacketInspector{
		sentPacketHandler:     onSent,
		receivedPacketHandler: onReceived,
	}, nil
}
