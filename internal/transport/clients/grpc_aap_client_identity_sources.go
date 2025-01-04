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
	"io"

	azapiv1aap "github.com/permguard/permguard/internal/agents/services/aap/endpoints/api/v1"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelaap "github.com/permguard/permguard/pkg/transport/models/aap"
)

// CreateIdentitySource creates a new identity source.
func (c *GrpcAAPClient) CreateIdentitySource(applicationID int64, name string) (*azmodelaap.IdentitySource, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identitySource, err := client.CreateIdentitySource(context.Background(), &azapiv1aap.IdentitySourceCreateRequest{ApplicationID: applicationID, Name: name})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentitySourceResponseToAgentIdentitySource(identitySource)
}

// UpdateIdentitySource updates an identity source.
func (c *GrpcAAPClient) UpdateIdentitySource(identitySource *azmodelaap.IdentitySource) (*azmodelaap.IdentitySource, error) {
	if identitySource == nil {
		return nil, azerrors.WrapSystemError(azerrors.ErrClientGeneric, "client: invalid identity source instance")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedIdentitySource, err := client.UpdateIdentitySource(context.Background(), &azapiv1aap.IdentitySourceUpdateRequest{
		IdentitySourceID: identitySource.IdentitySourceID,
		ApplicationID:    identitySource.ApplicationID,
		Name:             identitySource.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentitySourceResponseToAgentIdentitySource(updatedIdentitySource)
}

// DeleteIdentitySource deletes an identity source.
func (c *GrpcAAPClient) DeleteIdentitySource(applicationID int64, identitySourceID string) (*azmodelaap.IdentitySource, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identitySource, err := client.DeleteIdentitySource(context.Background(), &azapiv1aap.IdentitySourceDeleteRequest{ApplicationID: applicationID, IdentitySourceID: identitySourceID})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcIdentitySourceResponseToAgentIdentitySource(identitySource)
}

// FetchIdentitySources returns all identity sources.
func (c *GrpcAAPClient) FetchIdentitySources(page int32, pageSize int32, applicationID int64) ([]azmodelaap.IdentitySource, error) {
	return c.FetchIdentitySourcesBy(page, pageSize, applicationID, "", "")
}

// FetchIdentitySourcesByID returns all identity sources filtering by identity source id.
func (c *GrpcAAPClient) FetchIdentitySourcesByID(page int32, pageSize int32, applicationID int64, identitySourceID string) ([]azmodelaap.IdentitySource, error) {
	return c.FetchIdentitySourcesBy(page, pageSize, applicationID, identitySourceID, "")
}

// FetchIdentitySourcesByName returns all identity sources filtering by name.
func (c *GrpcAAPClient) FetchIdentitySourcesByName(page int32, pageSize int32, applicationID int64, name string) ([]azmodelaap.IdentitySource, error) {
	return c.FetchIdentitySourcesBy(page, pageSize, applicationID, "", name)
}

// FetchIdentitySourcesBy returns all identity sources filtering by identity source id and name.
func (c *GrpcAAPClient) FetchIdentitySourcesBy(page int32, pageSize int32, applicationID int64, identitySourceID string, name string) ([]azmodelaap.IdentitySource, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	identitySourceFetchRequest := &azapiv1aap.IdentitySourceFetchRequest{}
	identitySourceFetchRequest.Page = &page
	identitySourceFetchRequest.PageSize = &pageSize
	if applicationID > 0 {
		identitySourceFetchRequest.ApplicationID = applicationID
	}
	if name != "" {
		identitySourceFetchRequest.Name = &name
	}
	if identitySourceID != "" {
		identitySourceFetchRequest.IdentitySourceID = &identitySourceID
	}
	stream, err := client.FetchIdentitySources(context.Background(), identitySourceFetchRequest)
	if err != nil {
		return nil, err
	}
	identitySources := []azmodelaap.IdentitySource{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		identitySource, err := azapiv1aap.MapGrpcIdentitySourceResponseToAgentIdentitySource(response)
		if err != nil {
			return nil, err
		}
		identitySources = append(identitySources, *identitySource)
	}
	return identitySources, nil
}
