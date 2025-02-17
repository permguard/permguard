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
	LedgerType = "ledger"
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
	const errMsgBadRequest = "bad request for %s"
	if request == nil || request.Authorizationmodel == nil || request.Authorizationmodel.PolicyStore == nil {
		errMsg := fmt.Sprintf(errMsgBadRequest, "required fields")
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
	}
	if request.Authorizationmodel.ZoneID == 0 {
		errMsg := fmt.Sprintf(errMsgBadRequest, "zone id")
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
	}
	policyStore := request.Authorizationmodel.PolicyStore
	if strings.ToLower(policyStore.Type) != LedgerType {
		errMsg := fmt.Sprintf(errMsgBadRequest, "policy store type")
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
	}
	if len(strings.TrimSpace(policyStore.ID)) == 0 {
		errMsg := fmt.Sprintf(errMsgBadRequest, "policy store id")
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
	}
	expReq, err := authorizationCheckExpandAuthorizationCheckWithDefaults(request)
	if err != nil {
		errMsg := fmt.Sprintf(errMsgBadRequest, "the expanded request")
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
	}
	principal := request.Authorizationmodel.Principal
	if principal == nil {
		errMsg := fmt.Sprintf(errMsgBadRequest, "principal")
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
	}
	if len(strings.TrimSpace(principal.ID)) == 0 {
		errMsg := fmt.Sprintf(errMsgBadRequest, "principal id")
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
	}
	if azmodelspdp.IsValidIdentiyType(principal.Type) == false {
		errMsg := fmt.Sprintf(errMsgBadRequest, "principal type")
		return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
	}
	for _, evaluation := range expReq.Evaluations {
		if len(strings.TrimSpace(evaluation.Subject.ID)) == 0 {
			errMsg := fmt.Sprintf(errMsgBadRequest, "subject id")
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
		}
		if azmodelspdp.IsValidIdentiyType(evaluation.Subject.Type) == false {
			errMsg := fmt.Sprintf(errMsgBadRequest, "subject type")
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
		}
		if azmodelspdp.IsValidProperties(evaluation.Subject.Properties) == false {
			errMsg := fmt.Sprintf(errMsgBadRequest, "subject properties")
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
		}
		if len(strings.TrimSpace(evaluation.Resource.ID)) == 0 {
			errMsg := fmt.Sprintf(errMsgBadRequest, "resource id")
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
		}
		if len(strings.TrimSpace(evaluation.Resource.Type)) == 0 {
			errMsg := fmt.Sprintf(errMsgBadRequest, "resource type")
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
		}
		if azmodelspdp.IsValidProperties(evaluation.Resource.Properties) == false {
			errMsg := fmt.Sprintf(errMsgBadRequest, "resource properties")
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
		}
		if len(strings.TrimSpace(evaluation.Action.Name)) == 0 {
			errMsg := fmt.Sprintf(errMsgBadRequest, "action name")
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
		}
		if azmodelspdp.IsValidProperties(evaluation.Action.Properties) == false {
			errMsg := fmt.Sprintf(errMsgBadRequest, "action properties")
			return azmodelspdp.NewAuthorizationCheckErrorResponse(nil, azauthz.AuthzErrBadRequestCode, errMsg, errMsg), nil
		}
	}
	return s.storage.AuthorizationCheck(expReq)
}
