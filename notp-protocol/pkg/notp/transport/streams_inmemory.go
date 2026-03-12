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

package transport

import (
	"context"
	"errors"
	"sync"
	"time"

	aznotppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
)

// InMemoryStream simulates an in-memory stream for packet transmission with a fixed timeout.
type InMemoryStream struct {
	mu       sync.Mutex
	packets  []aznotppackets.Packet
	packetCh chan aznotppackets.Packet
	timeout  time.Duration
}

// TransmitPacket appends a packet to the in-memory stream.
func (t *InMemoryStream) TransmitPacket(packet *aznotppackets.Packet) error {
	if packet == nil {
		return errors.New("notp: cannot transmit a nil packet")
	}
	p := *packet
	t.mu.Lock()
	t.packets = append(t.packets, p)
	t.mu.Unlock()
	t.packetCh <- p
	return nil
}

// ReceivePacket retrieves the oldest packet from the in-memory stream, with a fixed timeout.
func (t *InMemoryStream) ReceivePacket() (*aznotppackets.Packet, error) {
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()
	select {
	case packet := <-t.packetCh:
		return &packet, nil
	case <-ctx.Done():
		return nil, errors.New("notp: timeout waiting for packet")
	}
}

// NewInMemoryStream creates and initializes a new in-memory stream with a fixed timeout.
func NewInMemoryStream(timeout time.Duration) (*InMemoryStream, error) {
	return &InMemoryStream{
		packets:  make([]aznotppackets.Packet, 0),
		packetCh: make(chan aznotppackets.Packet, 10),
		timeout:  timeout,
	}, nil
}
