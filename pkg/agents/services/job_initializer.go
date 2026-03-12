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
	"context"

	"github.com/permguard/permguard/pkg/agents/storage"
)

// JobInitializer is the service job factory.
type JobInitializer struct {
	service ServiceKind
	name    string
	run     func(context.Context, *ServiceContext, *storage.Connector) error
}

// NewJobInitializer creates a new service job factory.
func NewJobInitializer(service ServiceKind, name string, run func(context.Context, *ServiceContext, *storage.Connector) error) (JobInitializer, error) {
	return JobInitializer{
		service: service,
		name:    name,
		run:     run,
	}, nil
}

// Service returns the service kind.
func (j JobInitializer) Service() ServiceKind {
	return j.service
}

// Name returns the job name.
func (j JobInitializer) Name() string {
	return j.name
}

// Run returns the run function.
func (j JobInitializer) Run() func(context.Context, *ServiceContext, *storage.Connector) error {
	return j.run
}
