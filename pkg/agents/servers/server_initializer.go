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

package servers

import (
	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
)

// ServerInitializer is the server initializer.
type ServerInitializer interface {
	// Embeds the storage initializer.
	storage.StorageInitializer
	// Embeds the service initializer.
	services.ServiceInitializer
	// Host returns the service kind set as host.
	Host() services.HostKind
	// HostInfo returns the infos of the service kind set as host.
	HostInfo() *services.HostInfo
	// HasCentralStorage returns true if a central storage is required.
	HasCentralStorage() bool
}
