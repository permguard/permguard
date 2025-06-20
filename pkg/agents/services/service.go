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

package services

import (
	"github.com/permguard/permguard/pkg/agents/runtime"
)

// Serviceable must be implemented by all services.
type Serviceable interface {
	// Service returns the service kind.
	Service() ServiceKind
	// Endpoints returns the service endpoints.
	Endpoints() ([]EndpointInitializer, error)
	// ServiceConfigReader returns the service configuration reader.
	ServiceConfigReader() (runtime.ServiceConfigReader, error)
}
