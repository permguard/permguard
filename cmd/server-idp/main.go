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

package main

import (
	"fmt"

	azicli "github.com/permguard/permguard/internal/agents/cli"
	azictyservers "github.com/permguard/permguard/internal/agents/servers"
	azservices "github.com/permguard/permguard/pkg/agents/services"
)

func main() {
	// Run the command with the aap host kind.
	initializer, err := azictyservers.NewCommunityServerInitializer(azservices.HostIDP)
	if err != nil {
		panic(fmt.Sprintf("server: error creating server: %s", err.Error()))
	}
	azicli.Run(initializer, nil, nil)
}
