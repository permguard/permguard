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

package v1

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

func MapGrpcRepositoryResponseToAgentRepository(repository *RepositoryResponse) (*azmodels.Repository, error) {
	return &azmodels.Repository{
		RepositoryID: repository.RepositoryID,
		CreatedAt:    repository.CreatedAt.AsTime(),
		UpdatedAt:    repository.UpdatedAt.AsTime(),
		AccountID:    repository.AccountID,
		Name:         repository.Name,
		Ref:          repository.Ref,
	}, nil
}

// MapAgentRepositoryToGrpcRepositoryResponse maps the agent repository to the gRPC repository.
func MapAgentRepositoryToGrpcRepositoryResponse(repository *azmodels.Repository) (*RepositoryResponse, error) {
	return &RepositoryResponse{
		RepositoryID: repository.RepositoryID,
		CreatedAt:    timestamppb.New(repository.CreatedAt),
		UpdatedAt:    timestamppb.New(repository.UpdatedAt),
		AccountID:    repository.AccountID,
		Name:         repository.Name,
		Ref:          repository.Ref,
	}, nil
}

// MapPointerStringToString maps a pointer string to a string.
func MapPointerStringToString(str *string) string {
	response := ""
	if str != nil {
		response = *str
	}
	return response
}
