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
	"io"
	"time"

	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
)

// WireSendFunc wire send function.
type WireSendFunc func(packet *notppackets.Packet) error

// WireRecvFunc wire receive function.
type WireRecvFunc func() (*notppackets.Packet, error)

// WireStream wire stream.
type WireStream struct {
	sender   WireSendFunc
	receiver WireRecvFunc
	timeout  time.Duration
}

// TransmitPacket appends a packet to the in-wire stream.
func (t *WireStream) TransmitPacket(packet *notppackets.Packet) error {
	errCh := make(chan error, 1)

	go func() {
		if err := t.sender(packet); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
		return nil
	case <-time.After(t.timeout):
		return errors.New("notp: timeout sending packet")
	}
}

// ReceivePacket retrieves the oldest packet from the in-wire stream, with a fixed timeout.
func (t *WireStream) ReceivePacket() (*notppackets.Packet, error) {
	packetCh := make(chan *notppackets.Packet, 1)
	errCh := make(chan error, 1)

	go func() {
		packet, err := t.receiver()
		if err != nil {
			if err == io.EOF {
				errCh <- io.EOF
			} else {
				errCh <- err
			}
			return
		}
		packetCh <- packet
	}()

	select {
	case packet := <-packetCh:
		return packet, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(t.timeout):
		return nil, errors.New("notp: timeout waiting for packet")
	}
}

// NewWireStream creates and initializes a new in-wire stream with a fixed timeout.
func NewWireStream(sender WireSendFunc, receiver WireRecvFunc, timeout time.Duration) (*WireStream, error) {
	return &WireStream{
		sender:   sender,
		receiver: receiver,
		timeout:  timeout,
	}, nil
}
