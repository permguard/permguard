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
	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
)

const (
	// StatePacketType represents the type of the state packet.
	StatePacketType = uint32(10)

	// UnknownValue indicates that the value is unknown.
	UnknownValue = uint32(0)
	// RejectedValue indicates that the action was rejected.
	RejectedValue = uint32(1)
	// AcknowledgedValue indicates that the action was acknowledged.
	AcknowledgedValue = uint32(2)
	// ActiveDataStreamValue indicates that the data stream is active.
	ActiveDataStreamValue = uint32(3)
	// CompletedDataStreamValue indicates that the data stream is completed.
	CompletedDataStreamValue = uint32(4)

	// FlowIDValue represents the flow ID.
	FlowIDValue = uint16(10)

	// StartFlowMessage represents the notification of the flow.
	StartFlowMessage = uint16(100)
	// ActionResponseMessage represents the response to an action.
	ActionResponseMessage = uint16(101)
	// TerminateMessage represents the termination of the flow.
	TerminateMessage = uint16(102)

	// NotifyCurrentObjectStatesMessage represents the notification of the current object states.
	NotifyCurrentObjectStatesMessage = uint16(111)
	// RequestCurrentObjectsStateMessage represents the request for the current state.
	RequestCurrentObjectsStateMessage = uint16(112)
	// RespondCurrentStateMessage represents the response to the current state.
	RespondCurrentStateMessage = uint16(113)

	// NegotiationRequestMessage represents the negotiation request.
	NegotiationRequestMessage = uint16(141)
	// RespondNegotiationRequestMessage represents the response to the negotiation request.
	RespondNegotiationRequestMessage = uint16(142)

	// ExchangeDataStreamMessage represents the exchange of data stream.
	ExchangeDataStreamMessage = uint16(170)

	// CommitMessage represents the commit message.
	CommitMessage = uint16(200)
)

// StatePacket encapsulates the data structure for a base packet used in the protocol.
type StatePacket struct {
	MessageCode  uint16
	MessageValue uint64
	ErrorCode    uint16
}

// Type returns the packet type.
func (p *StatePacket) Type() uint64 {
	return notppackets.CombineUint32toUint64(StatePacketType, 0)
}

// HasAck returns true if the packet has an acknowledgment.
func (p *StatePacket) HasAck() bool {
	return notppackets.HasUint64AUint32(p.MessageValue, AcknowledgedValue) && !p.HasError()
}

// HasActiveDataStream returns true if the packet has an active data stream.
func (p *StatePacket) HasActiveDataStream() bool {
	return notppackets.HasUint64AUint32(p.MessageValue, ActiveDataStreamValue) && !p.HasError()
}

// HasCompletedDataStream returns true if the packet has a completed data stream.
func (p *StatePacket) HasCompletedDataStream() bool {
	return notppackets.HasUint64AUint32(p.MessageValue, CompletedDataStreamValue) && !p.HasError()
}

// HasError returns true if the packet has errors.
func (p *StatePacket) HasError() bool {
	return p.ErrorCode != 0
}

// Serialize serializes the packet into bytes.
func (p *StatePacket) Serialize() ([]byte, error) {
	data := notppackets.SerializeUint16(nil, p.MessageCode, notppackets.PacketNullByte)
	data = notppackets.SerializeUint64(data, p.MessageValue, notppackets.PacketNullByte)
	data = notppackets.SerializeUint16(data, p.ErrorCode, notppackets.PacketNullByte)
	return data, nil
}

// Deserialize deserializes the packet from bytes.
func (p *StatePacket) Deserialize(data []byte) error {
	var err error
	p.MessageCode, data, err = notppackets.DeserializeUint16(data, notppackets.PacketNullByte)
	if err != nil {
		return err
	}
	p.MessageValue, data, err = notppackets.DeserializeUint64(data, notppackets.PacketNullByte)
	if err != nil {
		return err
	}
	p.ErrorCode, _, err = notppackets.DeserializeUint16(data, notppackets.PacketNullByte)
	if err != nil {
		return err
	}
	return nil
}
