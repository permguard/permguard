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

package statemachines

import (
	"fmt"

	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	notpsmpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
)

// createStatePacket creates a state packet.
func createStatePacket(runtime *StateMachineRuntimeContext, messageCode uint16, messageValue uint64) (*notpsmpackets.StatePacket, *HandlerContext, error) {
	handlerCtx := &HandlerContext{
		flow:           runtime.GetFlowType(),
		bag:            runtime.bag,
		currentStateID: runtime.GetCurrentStateID(),
	}
	packet := &notpsmpackets.StatePacket{
		MessageCode:  messageCode,
		MessageValue: messageValue,
		ErrorCode:    0,
	}
	return packet, handlerCtx, nil
}

// shouldHandlePacket checks if the packet should be handled.
func shouldHandlePacket(packet *notpsmpackets.StatePacket) bool {
	return packet.MessageCode != notpsmpackets.ActionResponseMessage && packet.MessageCode != notpsmpackets.StartFlowMessage
}

// createAndHandleStatePacket creates a state packet and handles it.
func createAndHandleStatePacket(runtime *StateMachineRuntimeContext, messageCode uint16, messageValue uint64, packetables []notppackets.Packetable) (*notpsmpackets.StatePacket, []notppackets.Packetable, bool, bool, error) {
	statePacket, handlerCtx, err := createStatePacket(runtime, messageCode, messageValue)
	if err != nil {
		return nil, nil, false, false, fmt.Errorf("notp: failed to create state packet: %w", err)
	}
	var handledPacketables []notppackets.Packetable
	hasMore := false
	if shouldHandlePacket(statePacket) {
		handlerReturn, err := runtime.HandleStream(handlerCtx, statePacket, packetables)
		if handlerReturn != nil {
			if handlerReturn.Terminate {
				err2 := sendTermination(runtime)
				return nil, nil, false, true, err2
			}
			hasMore = handlerReturn.HasMore
			handledPacketables = handlerReturn.Packetables
		}
		if err != nil {
			err := sendTermination(runtime)
			return nil, nil, false, false, fmt.Errorf("notp: failed to handle created packet: %w", err)
		}
		statePacket.MessageValue = handlerReturn.MessageValue
		statePacket.ErrorCode = handlerReturn.ErrorCode
	} else {
		handledPacketables = packetables
	}
	return statePacket, handledPacketables, hasMore, false, nil
}

// createAndHandleAndStreamStatePacket creates a state packet, handles it, and streams it.
func createAndHandleAndStreamStatePacket(runtime *StateMachineRuntimeContext, messageCode uint16, packetables []notppackets.Packetable) (notppackets.Packetable, bool, error) {
	messageValue := notppackets.CombineUint32toUint64(notpsmpackets.UnknownValue, notpsmpackets.UnknownValue)
	return createAndHandleAndStreamStatePacketWithValue(runtime, messageCode, messageValue, packetables)
}

// createAndHandleAndStreamStatePacketWithValue creates a state packet with value, handles it, and streams it.
func createAndHandleAndStreamStatePacketWithValue(runtime *StateMachineRuntimeContext, messageCode uint16, messageValue uint64, packetables []notppackets.Packetable) (notppackets.Packetable, bool, error) {
	var packet *notpsmpackets.StatePacket
	hasMore := true
	for hasMore {
		statePacket, handledPacketable, handlerHasMore, terminate, err := createAndHandleStatePacket(runtime, messageCode, messageValue, packetables)
		if terminate {
			err2 := sendTermination(runtime)
			return nil, true, err2
		}
		if err != nil {
			err2 := sendTermination(runtime)
			return nil, false, fmt.Errorf("notp: failed to create and handle packet: %w", err2)
		}
		hasMore = handlerHasMore
		packet = statePacket
		streamPacketables := append([]notppackets.Packetable{statePacket}, handledPacketable...)
		err = runtime.SendStream(streamPacketables)
		if err != nil {
			err := sendTermination(runtime)
			return nil, false, err
		}
	}
	return packet, false, nil
}

// sendTermination sends a termination message.
func sendTermination(runtime *StateMachineRuntimeContext) error {
	statePacket := &notpsmpackets.StatePacket{
		MessageCode: notpsmpackets.TerminateMessage,
	}
	err := runtime.Send(statePacket)
	return err
}

// receiveAndHandleStatePacket receives a state packet and handles it.
func receiveAndHandleStatePacket(runtime *StateMachineRuntimeContext, expectedMessageCode uint16) (*notpsmpackets.StatePacket, []notppackets.Packetable, bool, error) {
	handlerCtx := &HandlerContext{
		flow:           runtime.GetFlowType(),
		bag:            runtime.bag,
		currentStateID: runtime.GetCurrentStateID(),
	}
	packetsStream, err := runtime.ReceiveStream()
	if err != nil {
		return nil, nil, false, fmt.Errorf("notp: failed to receive packets: %w", err)
	}
	statePacket := &notpsmpackets.StatePacket{}
	data, err := packetsStream[0].Serialize()
	if err != nil {
		return nil, nil, false, fmt.Errorf("notp: failed to serialize packet: %w", err)
	}
	err = statePacket.Deserialize(data)
	if err != nil {
		return nil, nil, false, fmt.Errorf("notp: failed to deserialize state packet: %w", err)
	}
	if statePacket.HasError() {
		return nil, nil, false, fmt.Errorf("notp: received state packet with error: %d", statePacket.ErrorCode)
	}
	if statePacket.MessageCode == notpsmpackets.TerminateMessage {
		return nil, nil, true, nil
	}
	if statePacket.MessageCode != expectedMessageCode {
		return nil, nil, false, fmt.Errorf("notp: received unexpected state code: %d", statePacket.MessageCode)
	}
	var handledPacketables []notppackets.Packetable
	if shouldHandlePacket(statePacket) {
		handlerReturn, err := runtime.HandleStream(handlerCtx, statePacket, packetsStream[1:])
		if handlerReturn != nil {
			if handlerReturn.Terminate {
				return nil, nil, true, nil
			}
			handledPacketables = handlerReturn.Packetables
		}
		if err != nil {
			return nil, nil, false, fmt.Errorf("notp: failed to handle created packet: %w", err)
		}
		statePacket.MessageValue = handlerReturn.MessageValue
		statePacket.ErrorCode = handlerReturn.ErrorCode
	} else {
		handledPacketables = packetsStream[1:]
	}
	return statePacket, handledPacketables, false, nil
}
