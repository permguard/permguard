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
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
)

// authorizationCheckExpandAuthorizationCheckWithDefaults expands the authorization check with defaults.
func authorizationCheckExpandAuthorizationCheckWithDefaults(request *azmodelspdp.AuthorizationCheckWithDefaultsRequest) (*azmodelspdp.AuthorizationCheckRequest, error) {
	expReq := &azmodelspdp.AuthorizationCheckRequest{}
	expReq.AuthorizationContext = request.AuthorizationContext

	if len(request.Evaluations) == 0 {
		expRequest := azmodelspdp.EvaluationRequest{
			Subject:  request.Subject,
			Resource: request.Resource,
			Action:   request.Action,
			Context:  request.Context,
		}
		expReq.Evaluations = []azmodelspdp.EvaluationRequest{expRequest}
	} else {
		expReq.Evaluations = []azmodelspdp.EvaluationRequest{}
		for _, evaluation := range request.Evaluations {
			expRequest := azmodelspdp.EvaluationRequest{
				Subject:  request.Subject,
				Resource: request.Resource,
				Action:   request.Action,
				Context:  request.Context,
			}
			if evaluation.Subject != nil {
				expRequest.Subject = evaluation.Subject
			}
			if evaluation.Resource != nil {
				expRequest.Resource = evaluation.Resource
			}
			if evaluation.Action != nil {
				expRequest.Action = evaluation.Action
			}
			if evaluation.Context != nil {
				expRequest.Context = evaluation.Context
			}
			expReq.Evaluations = append(expReq.Evaluations, expRequest)
		}
	}
	return expReq, nil
}

// authorizationCheckVerifyPrincipal verify principal for the authorization check.
func authorizationCheckVerifyPrincipal(principal *azmodelspdp.Principal, subject *azmodelspdp.Subject) bool {
	if principal == nil {
		return true
	}

	if principal.ID != subject.ID {
		return false
	} else if principal.Type != subject.Type {
		return false
	} else if principal.Source != subject.Source {
		return false
	}
	return true
}
