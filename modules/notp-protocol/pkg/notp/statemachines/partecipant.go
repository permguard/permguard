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
	"crypto/rand"
	"encoding/binary"
	"fmt"

	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	notpsmpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
)

// FlowType represents the type of operation that the NOTP protocol is performing.
type FlowType uint64

const (
	// FlowIDKey represents the flow ID key.
	FlowIDKey = "flowid"

	// UnknownFlowType represents an unknown state machine type.
	UnknownFlowType FlowType = 0
	// PushFlowType represents the push state machine type.
	PushFlowType FlowType = 1
	// PullFlowType represents the pull state machine type.
	PullFlowType FlowType = 2
	// DefaultFlowType represents the default operation type.
	DefaultFlowType FlowType = PushFlowType

	// StartFlowStateID represents the state ID for the start flow state.
	StartFlowStateID = uint16(10)
	// ProcessStartFlowStateID represents the state ID for the process start flow state.
	ProcessStartFlowStateID = uint16(11)
	// RequestObjectsStateID represents the state ID for the request objects state.
	RequestObjectsStateID = uint16(12)
	// ProcessRequestObjectsStateID represents the state ID for the process request objects state.
	ProcessRequestObjectsStateID = uint16(13)
	// NotifyObjectsStateID represents the state ID for the notify objects state.
	NotifyObjectsStateID = uint16(14)
	// ProcessNotifyObjectsStateID represents the state ID for the process notify objects state.
	ProcessNotifyObjectsStateID = uint16(15)
	// SubscriberNegotiationStateID represents the state ID for the subscriber negotiation state.
	SubscriberNegotiationStateID = uint16(16)
	// SubscriberDataStreamStateID represents the state ID for the subscriber data stream state.
	SubscriberDataStreamStateID = uint16(17)
	// SubscriberCommitStateID represents the state ID for the subscriber commit state.
	SubscriberCommitStateID = uint16(18)
	// PublisherNegotiationStateID represents the state ID for the publisher negotiation state.
	PublisherNegotiationStateID = uint16(19)
	// PublisherDataStreamStateID represents the state ID for the publisher data stream state.
	PublisherDataStreamStateID = uint16(20)
	// PublisherCommitStateID represents the published commit state ID.
	PublisherCommitStateID = uint16(21)
)

// defaultStateMap represents the default state map for the state machine.
var defaultStateMap = map[uint16]StateTransitionFunc{
	InitialStateID:               InitialState,
	FinalStateID:                 FinalState,
	StartFlowStateID:             startFlowState,
	ProcessStartFlowStateID:      processStartFlowState,
	RequestObjectsStateID:        requestObjectsState,
	ProcessRequestObjectsStateID: processRequestObjectsState,
	NotifyObjectsStateID:         notifyObjectsState,
	ProcessNotifyObjectsStateID:  processNotifyObjectsState,
	PublisherNegotiationStateID:  publisherNegotiationState,
	PublisherDataStreamStateID:   publisherDataStreamState,
	PublisherCommitStateID:       publisherCommitState,
	SubscriberNegotiationStateID: subscriberNegotiationState,
	SubscriberDataStreamStateID:  subscriberDataStreamState,
	SubscriberCommitStateID:      subscriberCommitState,
}

// generateFlowID generates a flow ID.
func generateFlowID() uint64 {
	var n uint64
	binary.Read(rand.Reader, binary.BigEndian, &n)
	return n
}

// terminateWithFinal terminates the state machine with a final state..
func terminateWithFinal(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: FinalStateID,
	}, nil
}

// startFlowState state to start the flow.
func startFlowState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	flowID := generateFlowID()
	flowPacket := &notpsmpackets.StatePacket{
		MessageCode:  notpsmpackets.FlowIDValue,
		MessageValue: flowID,
	}
	runtime.Set(FlowIDKey, flowID)
	_, terminate, err := createAndHandleAndStreamStatePacketWithValue(runtime, notpsmpackets.StartFlowMessage, uint64(runtime.flowType), []notppackets.Packetable{flowPacket})
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: start flow failed to create and handle start flow packet: %w", err)
	}
	statePacket, _, terminate, err := receiveAndHandleStatePacket(runtime, notpsmpackets.ActionResponseMessage)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: start flow failed to receive and handle action response packet: %w", err)
	}
	if !statePacket.HasAck() {
		return nil, fmt.Errorf("notp: start flow failed to receive ack in action response packet")
	}
	var stateID uint16
	switch runtime.GetFlowType() {
	case PushFlowType:
		stateID = NotifyObjectsStateID
	case PullFlowType:
		stateID = RequestObjectsStateID
	default:
		return nil, fmt.Errorf("notp: unknown flow type")
	}
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: stateID,
	}, nil
}

// processStartFlowState state to process the start flow.
func processStartFlowState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	statePacket, packetables, terminate, err := receiveAndHandleStatePacket(runtime, notpsmpackets.StartFlowMessage)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: process start flow failed to receive and handle start flow packet: %w", err)
	}
	flowPacket := &notpsmpackets.StatePacket{}
	data, err := packetables[0].Serialize()
	flowPacket.Deserialize(data)
	if flowPacket.MessageCode != notpsmpackets.FlowIDValue {
		return nil, fmt.Errorf("notp: process start flow failed to deserialize flow packet")
	}
	runtime.Set(FlowIDKey, flowPacket.MessageValue)
	messageValue := notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
	_, terminate, err = createAndHandleAndStreamStatePacketWithValue(runtime, notpsmpackets.ActionResponseMessage, messageValue, packetables)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: process start flow failed to create and handle action response packet: %w", err)
	}
	flowtype := FlowType(statePacket.MessageValue)
	runtime = runtime.WithFlow(flowtype)
	var stateID uint16
	switch runtime.GetFlowType() {
	case PushFlowType:
		stateID = ProcessNotifyObjectsStateID
	case PullFlowType:
		stateID = ProcessRequestObjectsStateID
	default:
		return nil, fmt.Errorf("notp: unknown flow type")
	}
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: stateID,
	}, nil
}

// requestObjectsState state to request the current state.
func requestObjectsState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	_, terminate, err := createAndHandleAndStreamStatePacket(runtime, notpsmpackets.RequestCurrentObjectsStateMessage, nil)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: request object failed to create and handle request current state packet: %w", err)
	}
	_, _, terminate, err = receiveAndHandleStatePacket(runtime, notpsmpackets.RespondCurrentStateMessage)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: request object failed to receive and handle respond current state packet: %w", err)
	}
	var stateID uint16
	switch runtime.GetFlowType() {
	case PullFlowType:
		stateID = SubscriberNegotiationStateID
	default:
		return nil, fmt.Errorf("notp: unknown flow type")
	}
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: stateID,
	}, nil
}

// processRequestObjectsState state to process the request for the current state.
func processRequestObjectsState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	_, packetables, terminate, err := receiveAndHandleStatePacket(runtime, notpsmpackets.RequestCurrentObjectsStateMessage)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: process request failed to receive and handle request current state packet: %w", err)
	}
	_, terminate, err = createAndHandleAndStreamStatePacket(runtime, notpsmpackets.RespondCurrentStateMessage, packetables)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: process request failed to create and handle respond current state packet: %w", err)
	}
	var stateID uint16
	switch runtime.GetFlowType() {
	case PullFlowType:
		stateID = PublisherNegotiationStateID
	default:
		return nil, fmt.Errorf("notp: unknown flow type")
	}
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: stateID,
	}, nil
}

// notifyObjectsState state to send the current state notification.
func notifyObjectsState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	_, terminate, err := createAndHandleAndStreamStatePacket(runtime, notpsmpackets.NotifyCurrentObjectStatesMessage, nil)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: notify object failed to create and handle notify current state packet: %w", err)
	}
	_, _, terminate, err = receiveAndHandleStatePacket(runtime, notpsmpackets.RespondCurrentStateMessage)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: notify object failed to receive and handle respond current state packet: %w", err)
	}
	var stateID uint16
	switch runtime.GetFlowType() {
	case PushFlowType:
		stateID = PublisherNegotiationStateID
	default:
		return nil, fmt.Errorf("notp: unknown flow type")
	}
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: stateID,
	}, nil
}

// processNotifyObjectsState state to process the current state notification.
func processNotifyObjectsState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	_, packetables, terminate, err := receiveAndHandleStatePacket(runtime, notpsmpackets.NotifyCurrentObjectStatesMessage)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: process notify failed to receive and handle notify current state packet: %w", err)
	}
	_, terminate, err = createAndHandleAndStreamStatePacket(runtime, notpsmpackets.RespondCurrentStateMessage, packetables)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: process notify failed to create and handle respond current state packet: %w", err)
	}
	var stateID uint16
	switch runtime.GetFlowType() {
	case PushFlowType:
		stateID = SubscriberNegotiationStateID
	default:
		return nil, fmt.Errorf("notp: unknown flow type")
	}
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: stateID,
	}, nil
}

// submitNegotiationResponse state to submit negotiation response.
func subscriberNegotiationState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	_, terminate, err := createAndHandleAndStreamStatePacket(runtime, notpsmpackets.NegotiationRequestMessage, nil)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: subscribe negotiation failed to create and handle notify current state packet: %w", err)
	}
	statePacket, _, terminate, err := receiveAndHandleStatePacket(runtime, notpsmpackets.RespondNegotiationRequestMessage)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: subscribe negotiation failed to receive and handle respond current state packet: %w", err)
	}
	if !statePacket.HasAck() {
		return nil, fmt.Errorf("notp: subscribe negotiation failed to receive ack in respond negotiation request packet")
	}
	stateID := SubscriberDataStreamStateID
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: stateID,
	}, nil
}

// submitNegotiationResponse state to submit negotiation response.
func publisherNegotiationState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	_, packetables, terminate, err := receiveAndHandleStatePacket(runtime, notpsmpackets.NegotiationRequestMessage)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: publusher negotiation failed to receive and handle notify current state packet: %w", err)
	}
	_, terminate, err = createAndHandleAndStreamStatePacket(runtime, notpsmpackets.RespondNegotiationRequestMessage, packetables)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: publusher negotiation failed to create and handle respond current state packet: %w", err)
	}
	stateID := PublisherDataStreamStateID
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: stateID,
	}, nil
}

// subscriberDataStreamState state to receive data stream.
func subscriberDataStreamState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	hasStream := true
	for hasStream {
		statePacket, _, terminate, err := receiveAndHandleStatePacket(runtime, notpsmpackets.ExchangeDataStreamMessage)
		if terminate {
			return terminateWithFinal(runtime)
		}
		if err != nil {
			return nil, fmt.Errorf("notp: subscriber data stream failed to receive and handle exchange data stream packet: %w", err)
		}
		hasStream = statePacket.HasActiveDataStream()
	}
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: SubscriberCommitStateID,
	}, nil
}

// publisherDataStreamState state to send data stream.
func publisherDataStreamState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	_, terminate, err := createAndHandleAndStreamStatePacket(runtime, notpsmpackets.ExchangeDataStreamMessage, nil)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: publisher data stream failed to create and handle respond current state packet: %w", err)
	}
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: PublisherCommitStateID,
	}, nil
}

// subscriberCommitState state to commit the current state.
func subscriberCommitState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	_, terminate, err := createAndHandleAndStreamStatePacket(runtime, notpsmpackets.CommitMessage, nil)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: publisher commit failed to create and handle respond current state packet: %w", err)
	}
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: FinalStateID,
	}, nil
}

// publisherCommitState state to commit the current state.
func publisherCommitState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	_, _, terminate, err := receiveAndHandleStatePacket(runtime, notpsmpackets.CommitMessage)
	if terminate {
		return terminateWithFinal(runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("notp: subscriber commit failed to receive and handle respond current state packet: %w", err)
	}
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: FinalStateID,
	}, nil
}
