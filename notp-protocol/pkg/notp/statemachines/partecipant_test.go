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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	notppackets "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	notpsmpackets "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines/packets"
	notptransport "github.com/permguard/permguard/notp-protocol/pkg/notp/transport"
)

// stateMachinesInfo represents the state machines and their respective packet logs.
type stateMachinesInfo struct {
	follower         *StateMachine
	followerSent     []notppackets.Packet
	followerReceived []notppackets.Packet

	leader         *StateMachine
	leaderSent     []notppackets.Packet
	leaderReceived []notppackets.Packet
}

// buildCommitStateMachines initializes and returns the follower and leader state machines.
func buildCommitStateMachines(assert *assert.Assertions, followerHandler HostHandler, leaderHandler HostHandler) *stateMachinesInfo {
	sMInfo := &stateMachinesInfo{
		followerSent:     []notppackets.Packet{},
		followerReceived: []notppackets.Packet{},
		leaderSent:       []notppackets.Packet{},
		leaderReceived:   []notppackets.Packet{},
	}

	onFollowerSent := func(packet *notppackets.Packet) {
		sMInfo.followerSent = append(sMInfo.followerSent, *packet)
	}
	onFollowerReceived := func(packet *notppackets.Packet) {
		sMInfo.followerReceived = append(sMInfo.followerReceived, *packet)
	}

	onLeaderSent := func(packet *notppackets.Packet) {
		sMInfo.leaderSent = append(sMInfo.leaderSent, *packet)
	}
	onLeaderReceived := func(packet *notppackets.Packet) {
		sMInfo.leaderReceived = append(sMInfo.leaderReceived, *packet)
	}

	followerStream, err := notptransport.NewInMemoryStream(5 * time.Second)
	assert.Nil(err, "Failed to initialize the follower transport stream")
	leaderStream, err := notptransport.NewInMemoryStream(5 * time.Second)
	assert.Nil(err, "Failed to initialize the leader transport stream")

	followerPacketLogger, err := notptransport.NewPacketInspector(onFollowerSent, onFollowerReceived)
	assert.Nil(err, "Failed to initialize the follower packet logger")
	followerTransport, err := notptransport.NewTransportLayer(leaderStream.TransmitPacket, followerStream.ReceivePacket, followerPacketLogger)
	assert.Nil(err, "Failed to initialize the follower transport layer")

	leaderPacketLogger, err := notptransport.NewPacketInspector(onLeaderSent, onLeaderReceived)
	assert.Nil(err, "Failed to initialize the leader packet logger")
	leaderTransport, err := notptransport.NewTransportLayer(followerStream.TransmitPacket, leaderStream.ReceivePacket, leaderPacketLogger)
	assert.Nil(err, "Failed to initialize the leader transport layer")

	followerSMachine, err := NewFollowerStateMachine(followerHandler, followerTransport)
	assert.Nil(err, "Failed to initialize the follower state machine")
	sMInfo.follower = followerSMachine

	leaderSMachine, err := NewLeaderStateMachine(leaderHandler, leaderTransport)
	assert.Nil(err, "Failed to initialize the leader state machine")
	sMInfo.leader = leaderSMachine

	return sMInfo
}

// TestPullProtocolExecution verifies the state machine execution for both follower and leader in the context of a pull operation.
func TestPullProtocolExecution(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name                string
		flowType            FlowType
		followerSent        int
		followerReceived    int
		leaderSent          int
		leaderReceived      int
		expectedFollowerIDs []uint16
		expectedLeaderIDs   []uint16
	}{
		{
			name:             "PullFlowType",
			flowType:         PullFlowType,
			followerSent:     4,
			followerReceived: 7,
			leaderSent:       7,
			leaderReceived:   4,
			expectedFollowerIDs: []uint16{
				RequestObjectsStateID,
				RequestObjectsStateID,
				SubscriberNegotiationStateID,
				SubscriberNegotiationStateID,
				SubscriberDataStreamStateID,
				SubscriberDataStreamStateID,
				SubscriberDataStreamStateID,
				SubscriberDataStreamStateID,
				SubscriberCommitStateID,
				SubscriberCommitStateID,
			},
			expectedLeaderIDs: []uint16{
				ProcessRequestObjectsStateID,
				ProcessRequestObjectsStateID,
				PublisherNegotiationStateID,
				PublisherNegotiationStateID,
				PublisherDataStreamStateID,
				PublisherDataStreamStateID,
				PublisherDataStreamStateID,
				PublisherDataStreamStateID,
				PublisherCommitStateID,
				PublisherCommitStateID,
			},
		},
		{
			name:             "PushFlowType",
			flowType:         PushFlowType,
			followerSent:     7,
			followerReceived: 4,
			leaderSent:       4,
			leaderReceived:   7,
			expectedFollowerIDs: []uint16{
				NotifyObjectsStateID,
				NotifyObjectsStateID,
				PublisherNegotiationStateID,
				PublisherNegotiationStateID,
				PublisherDataStreamStateID,
				PublisherDataStreamStateID,
				PublisherDataStreamStateID,
				PublisherDataStreamStateID,
				PublisherCommitStateID,
				PublisherCommitStateID,
			},
			expectedLeaderIDs: []uint16{
				ProcessNotifyObjectsStateID,
				ProcessNotifyObjectsStateID,
				SubscriberNegotiationStateID,
				SubscriberNegotiationStateID,
				SubscriberDataStreamStateID,
				SubscriberDataStreamStateID,
				SubscriberDataStreamStateID,
				SubscriberDataStreamStateID,
				SubscriberCommitStateID,
				SubscriberCommitStateID,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			followerIDs := []uint16{}
			leaderIDs := []uint16{}

			streamSize := 3
			followerHandler := func(handlerCtx *HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*HostHandlerReturn, error) {
				currentStateID := handlerCtx.GetCurrentStateID()
				followerIDs = append(followerIDs, currentStateID)
				packet := &notppackets.Packet{
					Data: []byte("sample data"),
				}
				handlerReturn := &HostHandlerReturn{
					Packetables: []notppackets.Packetable{packet},
				}
				if handlerCtx.GetCurrentStateID() == PublisherDataStreamStateID && handlerCtx.GetFlowType() == PushFlowType {
					if streamSize > 0 {
						handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.ActiveDataStreamValue)
						handlerReturn.HasMore = true
					} else {
						handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.CompletedDataStreamValue)
						handlerReturn.HasMore = false
					}
					streamSize--
				} else if handlerCtx.GetCurrentStateID() == SubscriberDataStreamStateID && handlerCtx.GetFlowType() == PullFlowType {
					handlerReturn.MessageValue = statePacket.MessageValue
				} else {
					handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
				}
				return handlerReturn, nil
			}

			leaderHandler := func(handlerCtx *HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*HostHandlerReturn, error) {
				currentStateID := handlerCtx.GetCurrentStateID()
				leaderIDs = append(leaderIDs, currentStateID)
				handlerReturn := &HostHandlerReturn{
					Packetables: packets,
				}
				if handlerCtx.GetCurrentStateID() == SubscriberDataStreamStateID && handlerCtx.GetFlowType() == PushFlowType {
					handlerReturn.MessageValue = statePacket.MessageValue
				} else if handlerCtx.GetCurrentStateID() == PublisherDataStreamStateID && handlerCtx.GetFlowType() == PullFlowType {
					if streamSize > 0 {
						handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.ActiveDataStreamValue)
						handlerReturn.HasMore = true
					} else {
						handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.CompletedDataStreamValue)
						handlerReturn.HasMore = false
					}
					streamSize--

				} else {
					handlerReturn.MessageValue = notppackets.CombineUint32toUint64(notpsmpackets.AcknowledgedValue, notpsmpackets.UnknownValue)
				}
				return handlerReturn, nil
			}

			sMInfo := buildCommitStateMachines(assert, followerHandler, leaderHandler)

			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				_, err := sMInfo.follower.Run(nil, test.flowType)
				assert.Nil(err, "Failed to run the follower state machine")
			}()

			go func() {
				defer wg.Done()
				_, err := sMInfo.leader.Run(nil, UnknownFlowType)
				assert.Nil(err, "Failed to run the leader state machine")
			}()

			wg.Wait()

			assert.Len(sMInfo.followerSent, test.followerSent, "Follower sent packets")
			assert.Len(sMInfo.followerReceived, test.followerReceived, "Follower received packets")
			assert.Len(sMInfo.leaderSent, test.leaderSent, "Leader sent packets")
			assert.Len(sMInfo.leaderReceived, test.leaderReceived, "Leader received packets")

			for i, id := range followerIDs {
				assert.Equal(test.expectedFollowerIDs[i], id, "Follower state ID")
			}
			for i, id := range leaderIDs {
				assert.Equal(test.expectedLeaderIDs[i], id, "Leader state ID")
			}
		})
	}
}
