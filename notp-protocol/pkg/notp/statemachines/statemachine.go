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
	"errors"

	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	notpsmpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
	notptransport "github.com/permguard/permguard/notp-protocol/pkg/notp/transport"
)

const (
	FinalStateID   = uint16(1)
	InitialStateID = uint16(2)
)

// HandlerContext holds the context of the handler.
type HandlerContext struct {
	flow           FlowType
	currentStateID uint16
	bag            map[string]interface{}
}

// GetFlowType returns the flow type of the handler context.
func (h *HandlerContext) GetFlowType() FlowType {
	return h.flow
}

// GetCurrentStateID returns the current state ID of the handler context.
func (h *HandlerContext) GetCurrentStateID() uint16 {
	return h.currentStateID
}

// Set stores a key-value pair in the runtime context of the state machine.
func (h *HandlerContext) Set(key string, value interface{}) {
	if h.bag == nil {
		h.bag = make(map[string]interface{})
	}
	h.bag[key] = value
}

// Get retrieves the value associated with the specified key from the runtime context.
func (h *HandlerContext) Get(key string) (any, bool) {
	if h.bag == nil {
		return nil, false
	}
	value, exists := h.bag[key]
	return value, exists
}

// PacketCreatorFunc is a function that creates a packet.
type PacketCreatorFunc func(*notpsmpackets.StatePacket) notppackets.Packetable

// HostHandlerReturn holds the return value of the host handler.
type HostHandlerReturn struct {
	HasMore      bool
	MessageValue uint64
	ErrorCode    uint16
	Packetables  []notppackets.Packetable
	Terminate    bool
}

// HostHandler defines a function type for handling packet.
type HostHandler func(*HandlerContext, *notpsmpackets.StatePacket, []notppackets.Packetable) (*HostHandlerReturn, error)

// StateTransitionInfo holds the information about the state transition.
type StateTransitionInfo struct {
	Runtime *StateMachineRuntimeContext
	StateID uint16
}

// StateTransitionFunc defines a function responsible for transitioning to the next state in the state machine.
type StateTransitionFunc func(runtimeIn *StateMachineRuntimeContext) (nextStateInfo *StateTransitionInfo, err error)

// InitialState defines the initial state of the state machine.
func InitialState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	return &StateTransitionInfo{
		Runtime: runtime,
		StateID: runtime.initialStateID,
	}, nil
}

// FinalState defines the final state of the state machine.
func FinalState(runtime *StateMachineRuntimeContext) (*StateTransitionInfo, error) {
	return &StateTransitionInfo{
		Runtime: runtime.WithFinal(),
		StateID: 0,
	}, nil
}

// StateMachineRuntimeContext holds the runtime context of the state machine.
type StateMachineRuntimeContext struct {
	inputValue     uint64
	isFinal        bool
	flowType       FlowType
	transportLayer *notptransport.TransportLayer
	statemap       map[uint16]StateTransitionFunc
	initialStateID uint16
	currentStateID uint16
	hostHandler    HostHandler
	bag            map[string]interface{}
}

// WithInput returns the state machine runtime context with the input value.
func (t *StateMachineRuntimeContext) WithInput(inputValue uint64) *StateMachineRuntimeContext {
	return &StateMachineRuntimeContext{
		inputValue:     inputValue,
		isFinal:        t.isFinal,
		flowType:       t.flowType,
		transportLayer: t.transportLayer,
		statemap:       t.statemap,
		initialStateID: t.initialStateID,
		currentStateID: t.currentStateID,
		hostHandler:    t.hostHandler,
		bag:            t.bag,
	}
}

// WithFlow returns the state machine runtime context with the flow type.
func (t *StateMachineRuntimeContext) WithFlow(flowType FlowType) *StateMachineRuntimeContext {
	return &StateMachineRuntimeContext{
		inputValue:     t.inputValue,
		isFinal:        t.isFinal,
		flowType:       flowType,
		transportLayer: t.transportLayer,
		statemap:       t.statemap,
		initialStateID: t.initialStateID,
		currentStateID: t.currentStateID,
		hostHandler:    t.hostHandler,
		bag:            t.bag,
	}
}

// withCurrentState returns the state machine runtime context with the current state.
func (t *StateMachineRuntimeContext) withCurrentState(currentStateID uint16) *StateMachineRuntimeContext {
	return &StateMachineRuntimeContext{
		inputValue:     t.inputValue,
		isFinal:        t.isFinal,
		flowType:       t.flowType,
		transportLayer: t.transportLayer,
		statemap:       t.statemap,
		initialStateID: t.initialStateID,
		currentStateID: currentStateID,
		hostHandler:    t.hostHandler,
		bag:            t.bag,
	}
}

// WithFinal returns the state machine runtime context with the final state.
func (t *StateMachineRuntimeContext) WithFinal() *StateMachineRuntimeContext {
	return &StateMachineRuntimeContext{
		inputValue:     t.inputValue,
		isFinal:        true,
		flowType:       t.flowType,
		transportLayer: t.transportLayer,
		statemap:       t.statemap,
		initialStateID: t.initialStateID,
		currentStateID: t.currentStateID,
		hostHandler:    t.hostHandler,
		bag:            t.bag,
	}
}

// IsFinal returns true if the state machine is in the final state.
func (t *StateMachineRuntimeContext) IsFinal() bool {
	return t.isFinal
}

// GetFlowType returns the flow type of the state machine.
func (t *StateMachineRuntimeContext) GetFlowType() FlowType {
	return t.flowType
}

// GetCurrentStateID returns the current state ID of the state machine.
func (t *StateMachineRuntimeContext) GetCurrentStateID() uint16 {
	return t.currentStateID
}

// Set stores a key-value pair in the runtime context of the state machine.
func (t *StateMachineRuntimeContext) Set(key string, value interface{}) {
	if t.bag == nil {
		t.bag = make(map[string]interface{})
	}
	t.bag[key] = value
}

// Get retrieves the value associated with the specified key from the runtime context.
func (t *StateMachineRuntimeContext) Get(key string) (any, bool) {
	if t.bag == nil {
		return nil, false
	}
	value, exists := t.bag[key]
	return value, exists
}

// Send sends a packet through the transport layer.
func (t *StateMachineRuntimeContext) Send(packetable notppackets.Packetable) error {
	return t.SendStream([]notppackets.Packetable{packetable})
}

// SendStream sends a packets through the transport layer.
func (t *StateMachineRuntimeContext) SendStream(packetables []notppackets.Packetable) error {
	return t.transportLayer.TransmitPacket(packetables)
}

// Receive retrieves a packet from the transport layer.
func (t *StateMachineRuntimeContext) Receive() (notppackets.Packetable, error) {
	packets, err := t.ReceiveStream()
	if err != nil {
		return nil, err
	}
	if len(packets) == 0 {
		return nil, errors.New("notp: received a nil packet")
	} else if len(packets) > 1 {
		return nil, errors.New("notp: received more than one packet")
	}
	return packets[0], nil
}

// ReceiveStream retrieves packets from the transport layer.
func (t *StateMachineRuntimeContext) ReceiveStream() ([]notppackets.Packetable, error) {
	return t.transportLayer.ReceivePacket()
}

// Handle handles the packet for the state machine.
func (t *StateMachineRuntimeContext) Handle(handlerCtx *HandlerContext, statePacket *notpsmpackets.StatePacket) (*HostHandlerReturn, error) {
	return t.HandleStream(handlerCtx, statePacket, nil)
}

// HandleStream handles a packet stream for the state machine.
func (t *StateMachineRuntimeContext) HandleStream(handlerCtx *HandlerContext, statePacket *notpsmpackets.StatePacket, packetables []notppackets.Packetable) (*HostHandlerReturn, error) {
	if packetables == nil {
		packetables = []notppackets.Packetable{}
	}
	return t.hostHandler(handlerCtx, statePacket, packetables)
}

// StateMachine orchestrates the execution of state transitions.
type StateMachine struct {
	runtime *StateMachineRuntimeContext
}

// Run starts and runs the state machine through its states until termination.
func (m *StateMachine) Run(bag map[string]any, inputValue FlowType) (*StateMachineRuntimeContext, error) {
	if bag != nil {
		m.runtime.bag = bag
	}
	runtime := m.runtime
	runtime = runtime.WithFlow(inputValue)
	stateID := runtime.initialStateID
	state := m.runtime.statemap[runtime.initialStateID]
	for state != nil {
		runtime = runtime.withCurrentState(stateID)
		nextStateInfo, err := state(runtime)
		if err != nil {
			return nil, err
		}
		runtime = nextStateInfo.Runtime
		if runtime.IsFinal() {
			break
		}
		stateID = nextStateInfo.StateID
		state = m.runtime.statemap[nextStateInfo.StateID]
	}
	return runtime, nil
}

// NewStateMachine creates and initializes a new state machine with the given initial state and transport layer.
func NewStateMachine(statemap map[uint16]StateTransitionFunc, initialStateID uint16, hostHandler HostHandler, transportLayer *notptransport.TransportLayer) (*StateMachine, error) {
	if statemap == nil {
		return nil, errors.New("notp: state map cannot be nil")
	}
	if statemap[initialStateID] == nil {
		return nil, errors.New("notp: initial state does not exist in the state map")
	}
	if hostHandler == nil {
		return nil, errors.New("notp: decision handler cannot be nil")
	}
	if transportLayer == nil {
		return nil, errors.New("notp: transport layer cannot be nil")
	}
	return &StateMachine{
		runtime: &StateMachineRuntimeContext{
			inputValue:     0,
			isFinal:        false,
			flowType:       0,
			transportLayer: transportLayer,
			statemap:       statemap,
			initialStateID: initialStateID,
			currentStateID: initialStateID,
			hostHandler:    hostHandler,
		},
	}, nil
}
