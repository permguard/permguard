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

package grpcclients

import (
	"context"
	"errors"

	azapiv1aap "github.com/permguard/permguard/internal/agents/services/aap/endpoints/api/v1"
	azmodels "github.com/permguard/permguard/pkg/agents/models"
)

// CreateIdentitySource creates a new identity source.
func (c *GrpcAAPClient) CreateIdentitySource(accountID int64, name string) (*azmodels.IdentitySource, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identitySource, err := client.CreateIdentitySource(context.Background(), &azapiv1aap.IdentitySourceCreateRequest{AccountID: accountID, Name: name})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentitySourceResponseToAgentIdentitySource(identitySource)
}

// UpdateIdentitySource updates an identity source.
func (c *GrpcAAPClient) UpdateIdentitySource(identitySource *azmodels.IdentitySource) (*azmodels.IdentitySource, error) {
	if identitySource == nil {
		return nil, errors.New("client: invalid identity source instance")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedIdentitySource, err := client.UpdateIdentitySource(context.Background(), &azapiv1aap.IdentitySourceUpdateRequest{
		IdentitySourceID: identitySource.IdentitySourceID,
		AccountID:        identitySource.AccountID,
		Name:             identitySource.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentitySourceResponseToAgentIdentitySource(updatedIdentitySource)
}

// DeleteIdentitySource deletes an identity source.
func (c *GrpcAAPClient) DeleteIdentitySource(accountID int64, identitySourceID string) (*azmodels.IdentitySource, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identitySource, err := client.DeleteIdentitySource(context.Background(), &azapiv1aap.IdentitySourceDeleteRequest{AccountID: accountID, IdentitySourceID: identitySourceID})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentitySourceResponseToAgentIdentitySource(identitySource)
}

// FetchIdentitySources returns all the identity sources.
func (c *GrpcAAPClient) FetchIdentitySources(accountID int64) ([]azmodels.IdentitySource, error) {
	return c.FetchIdentitySourcesBy(accountID, "", "")
}

// FetchIdentitySourcesByID returns all identity sources filtering by identity source id.
func (c *GrpcAAPClient) FetchIdentitySourcesByID(accountID int64, identitySourceID string) ([]azmodels.IdentitySource, error) {
	return c.FetchIdentitySourcesBy(accountID, identitySourceID, "")
}

// FetchIdentitySourcesByName returns all identity sources filtering by name.
func (c *GrpcAAPClient) FetchIdentitySourcesByName(accountID int64, name string) ([]azmodels.IdentitySource, error) {
	return c.FetchIdentitySourcesBy(accountID, "", name)
}

// FetchIdentitySourcesBy returns all identity sources filtering by identity source id and name.
func (c *GrpcAAPClient) FetchIdentitySourcesBy(accountID int64, identitySourceID string, name string) ([]azmodels.IdentitySource, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identitySourceGetRequest := &azapiv1aap.IdentitySourceGetRequest{}
	if accountID > 0 {
		identitySourceGetRequest.AccountID = accountID
	}
	if name != "" {
		identitySourceGetRequest.Name = &name
	}
	if identitySourceID != "" {
		identitySourceGetRequest.IdentitySourceID = &identitySourceID
	}
	identitySourceList, err := client.FetchIdentitySources(context.Background(), identitySourceGetRequest)
	if err != nil {
		return nil, err
	}
	identitySources := make([]azmodels.IdentitySource, len(identitySourceList.IdentitySources))
	for i, gIdentitySource := range identitySourceList.IdentitySources {
		identitySource, err := azapiv1aap.MapGrpcIdentitySourceResponseToAgentIdentitySource(gIdentitySource)
		if err != nil {
			return nil, err
		}
		identitySources[i] = *identitySource
	}
	return identitySources, nil
}
