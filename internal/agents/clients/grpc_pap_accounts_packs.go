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

	azpap "github.com/permguard/permguard/internal/agents/services/pap"
	notpstatemachines "github.com/permguard/permguard-notp-protocol/pkg/notp/statemachines"
)

// UploadPack uploads a pack.
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

	timeout := 30 * time.Second
	stateMachine, err := azpap.CreateWiredStateMachine(stream, timeout)
	if err != nil {
		return err
	}
	err = stateMachine.Run(notpstatemachines.PushFlowType)
	if err != nil {
		return err
	}
	return nil
}
