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

package controllers

import (
	"strings"

	azservices "github.com/permguard/permguard/pkg/agents/services"
	azStorage "github.com/permguard/permguard/pkg/agents/storage"
	azauthz "github.com/permguard/permguard/pkg/authorization"
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
)

type PDPController struct {
	ctx     *azservices.ServiceContext
	storage azStorage.PDPCentralStorage
}

// Setup initializes the service.
func (s PDPController) Setup() error {
	return nil
}

// NewPDPController creates a new PDP controller.
func NewPDPController(serviceContext *azservices.ServiceContext, storage azStorage.PDPCentralStorage) (*PDPController, error) {
	service := PDPController{
		ctx:     serviceContext,
		storage: storage,
	}
	return &service, nil
}

// AuthorizationCheck checks if the request is authorized.
func (s PDPController) AuthorizationCheck(request *azmodelspdp.AuthorizationCheckWithDefaultsRequest) (*azmodelspdp.AuthorizationCheckResponse, error) {
	if request == nil || request.AuthorizationContext == nil || request.AuthorizationContext.PolicyStore == nil {
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, azauthz.AuthzErrBadRequestMessage, azauthz.AuthzErrBadRequestMessage), nil
	}
	policyStore := request.AuthorizationContext.PolicyStore
	if strings.ToLower(policyStore.Type) != "ledger" {
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, azauthz.AuthzErrBadRequestMessage, azauthz.AuthzErrBadRequestMessage), nil
	}
	expReq, err := authorizationCheckExpandAuthorizationCheckWithDefaults(request)
	if err != nil {
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, err.Error(), azauthz.AuthzErrBadRequestMessage), nil
	}
	for _, evaluation := range expReq.Evaluations {
		if !authorizationCheckVerifyPrincipal(request.AuthorizationContext.Principal, evaluation.Subject) {
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrUnauthorizedCode, azauthz.AuthzErrUnauthorizedMessage, azauthz.AuthzErrUnauthorizedMessage), nil
		}
	}
	return s.storage.AuthorizationCheck(expReq)
}
