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
	"time"

	azapiv1pap "github.com/permguard/permguard/internal/agents/services/pap/endpoints/api/v1"

	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
	notpsmpackets "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines/packets"
	notptransport "github.com/permguard/permguard-notp-protocol/pkg/notp/transport"
)

// UploadPack receives a pack.
func (c *GrpcPAPClient) UploadPack() error {
	client, err := c.createGRPCClient()
	if err != nil {
		return err
	}
	stream, err := client.UploadPack(context.Background())
	if err != nil {
		return err
	}
	defer stream.CloseSend()

	var sender notptransport.WireSendFunc = func(packet *notppackets.Packet) error {
		pack := &azapiv1pap.PackMessage{
			Data: packet.Data,
		}
		return stream.Send(pack)
	}
	var receiver notptransport.WireRecvFunc = func() (*notppackets.Packet, error) {
		pack, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		return &notppackets.Packet{Data: pack.Data}, nil
	}
	transportStream, err := notptransport.NewWireStream(sender, receiver, 1 * time.Second)
	if err != nil {
		return err
	}
	transportLayer, err := notptransport.NewTransportLayer(transportStream.TransmitPacket, transportStream.ReceivePacket, nil)
	if err != nil {
		return err
	}
	var hostHandler notpstatemachines.HostHandler = func(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
		handlerReturn := &notpstatemachines.HostHandlerRuturn {
			Packetables: packets,
		}
		return handlerReturn, nil
	}
	stateMachine, err := notpstatemachines.NewFollowerStateMachine(hostHandler, transportLayer)
	if err != nil {
		return err
	}
	err = stateMachine.Run(notpstatemachines.PushFlowType)
	if err != nil {
		return err
	}
	return nil
}
