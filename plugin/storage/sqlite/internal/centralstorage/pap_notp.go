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

package centralstorage

import (
	notppackets "github.com/permguard/permguard-notp-protocol/pkg/notp/packets"
	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
	notpsmpackets "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines/packets"
)

// OnPushHandleNotifyCurrentState notifies the current state.
func (s SQLiteCentralStoragePAP) OnPushHandleNotifyCurrentState(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	return handlerReturn, nil
}

// OnPushSendNotifyCurrentStateResponse handles the current state response.
func (s SQLiteCentralStoragePAP) OnPushSendNotifyCurrentStateResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	return handlerReturn, nil
}

// OnPushSendNegotiationRequest sends the negotiation request.
func (s SQLiteCentralStoragePAP) OnPushSendNegotiationRequest(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	return handlerReturn, nil
}

// OnPushHandleNegotiationResponse handles the negotiation response.
func (s SQLiteCentralStoragePAP) OnPushHandleNegotiationResponse(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error) {
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	return handlerReturn, nil
}

// OnPushHandleExchangeDataStream exchanges the data stream.
func (s SQLiteCentralStoragePAP) OnPushHandleExchangeDataStream(handlerCtx *notpstatemachines.HandlerContext, statePacket *notpsmpackets.StatePacket, packets []notppackets.Packetable) (*notpstatemachines.HostHandlerRuturn, error){
	handlerReturn := &notpstatemachines.HostHandlerRuturn{
		Packetables: packets,
	}
	return handlerReturn, nil
}
