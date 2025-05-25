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
	"time"

	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
)

// InMemoryStream simulates an in-memory stream for packet transmission with a fixed timeout.
type InMemoryStream struct {
	packets  []notppackets.Packet
	packetCh chan notppackets.Packet
	timeout  time.Duration
}

// TransmitPacket appends a packet to the in-memory stream.
func (t *InMemoryStream) TransmitPacket(packet *notppackets.Packet) error {
	if packet == nil {
		return errors.New("notp: cannot transmit a nil packet")
	}
	t.packets = append(t.packets, *packet)
	t.packetCh <- *packet
	return nil
}

// ReceivePacket retrieves the oldest packet from the in-memory stream, with a fixed timeout.
func (t *InMemoryStream) ReceivePacket() (*notppackets.Packet, error) {
	select {
	case packet := <-t.packetCh:
		return &packet, nil
	case <-time.After(t.timeout):
		return nil, errors.New("notp: timeout waiting for packet")
	}
}

// NewInMemoryStream creates and initializes a new in-memory stream with a fixed timeout.
func NewInMemoryStream(timeout time.Duration) (*InMemoryStream, error) {
	return &InMemoryStream{
		packets:  make([]notppackets.Packet, 0),
		packetCh: make(chan notppackets.Packet, 10),
		timeout:  timeout,
	}, nil
}
