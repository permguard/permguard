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
)

// ReceivePack receives a pack.
func (c *GrpcPAPClient) ReceivePack() error {
	client, err := c.createGRPCClient()
	if err != nil {
		return err
	}
	stream, err := client.ReceivePack(context.Background())
	if err != nil {
		return err
	}
	defer stream.CloseSend()

	go func() {
		for {
			res, err := stream.Recv()
			if err != nil {
				print(err)
			}
			print(string(res.Data))
		}
	}()

	for {
		pack := &azapiv1pap.PackMessage{
			Data: []byte(time.Now().Format(time.RFC3339)),
		}
		if err := stream.Send(pack); err != nil {
			return err
		}
		time.Sleep(1 * time.Second)
	}
}
