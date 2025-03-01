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
	"fmt"
	"strings"

	azservices "github.com/permguard/permguard/pkg/agents/services"
	azStorage "github.com/permguard/permguard/pkg/agents/storage"
	azauthz "github.com/permguard/permguard/pkg/authorization"
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
)

const (
	// LedgerKind is the kind of the policy store.
	LedgerKind = "ledger"
)

// PDPController is the controller for the PDP service.
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
	if request == nil || request.AuthorizationModel == nil || request.AuthorizationModel.PolicyStore == nil {
		errMsg := fmt.Sprintf("%s the required fields", azauthz.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
	}
	if request.AuthorizationModel.ZoneID == 0 {
		errMsg := fmt.Sprintf("%s for the zone id", azauthz.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
	}
	policyStore := request.AuthorizationModel.PolicyStore
	if len(policyStore.Kind) == 0 {
		policyStore.Kind = LedgerKind
	}
	if strings.ToLower(policyStore.Kind) != LedgerKind {
		errMsg := fmt.Sprintf("%s for the policy store kind", azauthz.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
	}
	if len(strings.TrimSpace(policyStore.ID)) == 0 {
		errMsg := fmt.Sprintf("%s for the policy store id", azauthz.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
	}
	expReq, err := authorizationCheckExpandAuthorizationCheckWithDefaults(request)
	if err != nil {
		errMsg := fmt.Sprintf("%s for the expanded request", azauthz.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
	}
	principal := request.AuthorizationModel.Principal
	if principal == nil {
		errMsg := fmt.Sprintf("%s for the principal", azauthz.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
	}
	if len(strings.TrimSpace(principal.ID)) == 0 {
		errMsg := fmt.Sprintf("%s for the principal id", azauthz.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
	}
	if azmodelspdp.IsValidIdentiyType(principal.Type) == false {
		errMsg := fmt.Sprintf("%s for the principal type", azauthz.AuthzErrBadRequestMessage)
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
	}
	for _, evaluation := range expReq.Evaluations {
		if len(strings.TrimSpace(evaluation.Subject.ID)) == 0 {
			errMsg := fmt.Sprintf("%s for the the subject id", azauthz.AuthzErrBadRequestMessage)
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
		}
		if azmodelspdp.IsValidIdentiyType(evaluation.Subject.Type) == false {
			errMsg := fmt.Sprintf("%s for the the subject type", azauthz.AuthzErrBadRequestMessage)
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
		}
		if azmodelspdp.IsValidProperties(evaluation.Subject.Properties) == false {
			errMsg := fmt.Sprintf("%s for the the subject properties", azauthz.AuthzErrBadRequestMessage)
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
		}
		if len(strings.TrimSpace(evaluation.Resource.ID)) == 0 {
			errMsg := fmt.Sprintf("%s for the the resource id", azauthz.AuthzErrBadRequestMessage)
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
		}
		if len(strings.TrimSpace(evaluation.Resource.Type)) == 0 {
			errMsg := fmt.Sprintf("%s for the the resource type", azauthz.AuthzErrBadRequestMessage)
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
		}
		if azmodelspdp.IsValidProperties(evaluation.Resource.Properties) == false {
			errMsg := fmt.Sprintf("%s for the the resource properties", azauthz.AuthzErrBadRequestMessage)
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
		}
		if len(strings.TrimSpace(evaluation.Action.Name)) == 0 {
			errMsg := fmt.Sprintf("%s for the the action name", azauthz.AuthzErrBadRequestMessage)
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
		}
		if azmodelspdp.IsValidProperties(evaluation.Action.Properties) == false {
			errMsg := fmt.Sprintf("%s for the the action properties", azauthz.AuthzErrBadRequestMessage)
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestMessage), nil
		}
	}
	return s.storage.AuthorizationCheck(expReq)
}
