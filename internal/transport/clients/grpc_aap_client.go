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

// CreateApplication creates a new application.
func (c *GrpcAAPClient) CreateApplication(name string) (*azmodelaap.Application, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	application, err := client.CreateApplication(context.Background(), &azapiv1aap.ApplicationCreateRequest{Name: name})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcApplicationResponseToAgentApplication(application)
}

// UpdateApplication updates an application.
func (c *GrpcAAPClient) UpdateApplication(application *azmodelaap.Application) (*azmodelaap.Application, error) {
	if application == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrClientGeneric, "invalid application instance")
	}
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	updatedApplication, err := client.UpdateApplication(context.Background(), &azapiv1aap.ApplicationUpdateRequest{
		ApplicationID: application.ApplicationID,
		Name:          application.Name,
	})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcApplicationResponseToAgentApplication(updatedApplication)
}

// DeleteApplication deletes an application.
func (c *GrpcAAPClient) DeleteApplication(applicationID int64) (*azmodelaap.Application, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	application, err := client.DeleteApplication(context.Background(), &azapiv1aap.ApplicationDeleteRequest{ApplicationID: applicationID})
	if err != nil {
		return nil, err
	}
	return azapiv1aap.MapGrpcApplicationResponseToAgentApplication(application)
}

// FetchApplications returns all applications.
func (c *GrpcAAPClient) FetchApplications(page int32, pageSize int32) ([]azmodelaap.Application, error) {
	return c.FetchApplicationsBy(page, pageSize, 0, "")
}

// FetchApplicationsByID returns all applications filtering by application id.
func (c *GrpcAAPClient) FetchApplicationsByID(page int32, pageSize int32, applicationID int64) ([]azmodelaap.Application, error) {
	return c.FetchApplicationsBy(page, pageSize, applicationID, "")
}

// FetchApplicationsByName returns all applications filtering by name.
func (c *GrpcAAPClient) FetchApplicationsByName(page int32, pageSize int32, name string) ([]azmodelaap.Application, error) {
	return c.FetchApplicationsBy(page, pageSize, 0, name)
}

// FetchApplicationsBy returns all applications filtering by application id and name.
func (c *GrpcAAPClient) FetchApplicationsBy(page int32, pageSize int32, applicationID int64, name string) ([]azmodelaap.Application, error) {
	client, err := c.createGRPCClient()
	if err != nil {
		return nil, err
	}
	applicationFetchRequest := &azapiv1aap.ApplicationFetchRequest{}
	applicationFetchRequest.Page = &page
	applicationFetchRequest.PageSize = &pageSize
	if applicationID > 0 {
		applicationFetchRequest.ApplicationID = &applicationID
	}
	if name != "" {
		applicationFetchRequest.Name = &name
	}
	stream, err := client.FetchApplications(context.Background(), applicationFetchRequest)
	if err != nil {
		return nil, err
	}
	applications := []azmodelaap.Application{}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		application, err := azapiv1aap.MapGrpcApplicationResponseToAgentApplication(response)
		if err != nil {
			return nil, err
		}
		applications = append(applications, *application)
	}
	return applications, nil
}
