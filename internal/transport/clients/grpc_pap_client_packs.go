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

package clients

import (
	"context"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	papv1 "github.com/permguard/permguard/internal/agents/services/pap/endpoints/api/v1"

	notpsm "github.com/permguard/permguard/internal/transport/notp/statemachines"
	notppkts "github.com/permguard/permguard/notp-protocol/pkg/notp/packets"
	statemachines "github.com/permguard/permguard/notp-protocol/pkg/notp/statemachines"
	notpxport "github.com/permguard/permguard/notp-protocol/pkg/notp/transport"
)

const (
	// DefaultTimeout is the default timeout for the wired state machine.
	DefaultTimeout = 30 * time.Second
)

// createWiredStateMachine creates a wired state machine.
func (c *GrpcPAPClient) createWiredStateMachine(stream grpc.BidiStreamingClient[papv1.PackMessage, papv1.PackMessage], hostHandler statemachines.HostHandler) (*statemachines.StateMachine, error) {
	var sender notpxport.WireSendFunc = func(packet *notppkts.Packet) error {
		pack := &papv1.PackMessage{
			Data: packet.Data,
		}
		return stream.Send(pack)
	}
	var receiver notpxport.WireRecvFunc = func() (*notppkts.Packet, error) {
		pack, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		return &notppkts.Packet{Data: pack.Data}, nil
	}
	transportStream, err := notpxport.NewWireStream(sender, receiver, DefaultTimeout)
	if err != nil {
		return nil, err
	}
	transportLayer, err := notpxport.NewTransportLayer(transportStream.TransmitPacket, transportStream.ReceivePacket, nil)
	if err != nil {
		return nil, err
	}
	stateMachine, err := statemachines.NewFollowerStateMachine(hostHandler, transportLayer)
	if err != nil {
		return nil, err
	}
	return stateMachine, nil
}

// NOTPStream handles bidirectional stream using the NOTP protocol.
func (c *GrpcPAPClient) NOTPStream(hostHandler statemachines.HostHandler, zoneID int64, ledgerID string, bag map[string]any, flowType statemachines.FlowType) (*statemachines.StateMachineRuntimeContext, error) {
	client, conn, err := c.createGRPCClient()
	defer conn.Close()
	if err != nil {
		return nil, err
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), notpsm.ZoneIDKey, strconv.FormatInt(zoneID, 10), notpsm.LedgerIDKey, ledgerID)
	stream, err := client.NOTPStream(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = stream.CloseSend() }()

	stateMachine, err := c.createWiredStateMachine(stream, hostHandler)
	if err != nil {
		return nil, err
	}
	return stateMachine.Run(bag, flowType)
}
