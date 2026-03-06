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

	"github.com/permguard/permguard/pkg/transport/models/pdp"
	"github.com/permguard/permguard/ztauthstar/pkg/authzen"
)

// evaluationInput is a flattened and validated view of a single evaluation request.
type evaluationInput struct {
	ZoneID             int64
	PolicyStoreKind    string
	PolicyStoreID      string
	HasPrincipal       bool
	PrincipalID        string
	PrincipalType      string
	SubjectID          string
	SubjectType        string
	SubjectProperties  map[string]any
	ResourceID         string
	ResourceType       string
	ResourceProperties map[string]any
	ActionName         string
	ActionProperties   map[string]any
}

// validationRule defines a single field validation check.
type validationRule struct {
	ok      bool
	message string
}

// rules returns the ordered list of validation rules for this input.
// Rules are evaluated in order; the first failing rule produces the error response.
func (e *evaluationInput) rules() []validationRule {
	return []validationRule{
		{ok: e.ZoneID != 0, message: "invalid zone id"},
		{ok: strings.ToLower(e.PolicyStoreKind) == LedgerKind, message: "invalid zone type"},
		{ok: len(strings.TrimSpace(e.PolicyStoreID)) > 0, message: "invalid policy store id"},
		{ok: e.HasPrincipal, message: "invalid principal"},
		{ok: len(strings.TrimSpace(e.PrincipalID)) > 0, message: "invalid the principal id"},
		{ok: pdp.IsValidIdentityType(e.PrincipalType), message: "invalid the principal type"},
		{ok: len(strings.TrimSpace(e.SubjectID)) > 0, message: "invalid subject id"},
		{ok: pdp.IsValidIdentityType(e.SubjectType), message: "invalid subject type"},
		{ok: pdp.IsValidProperties(e.SubjectProperties), message: "invalid subject properties"},
		{ok: len(strings.TrimSpace(e.ResourceID)) > 0, message: "invalid resource id"},
		{ok: len(strings.TrimSpace(e.ResourceType)) > 0, message: "invalid resource type"},
		{ok: pdp.IsValidProperties(e.ResourceProperties), message: "invalid resource properties"},
		{ok: len(strings.TrimSpace(e.ActionName)) > 0, message: "invalid action name"},
		{ok: pdp.IsValidProperties(e.ActionProperties), message: "invalid action properties"},
	}
}

// validateEvaluation validates a single evaluation input.
// Returns nil on success, or an *EvaluationResponse with the first error on failure.
func validateEvaluation(requestID string, input *evaluationInput) *pdp.EvaluationResponse {
	for _, rule := range input.rules() {
		if !rule.ok {
			errMsg := fmt.Sprintf("%s: %s", authzen.AuthzErrBadRequestMessage, rule.message)
			return pdp.NewEvaluationErrorResponse(requestID, authzen.AuthzErrBadRequestCode, errMsg, authzen.AuthzErrBadRequestMessage)
		}
	}
	return nil
}

// buildEvaluationInput constructs an evaluationInput from request-level and evaluation-level data.
func buildEvaluationInput(authzModel *pdp.AuthorizationModelRequest, evaluation *pdp.EvaluationRequest) *evaluationInput {
	input := &evaluationInput{
		ZoneID: authzModel.ZoneID,
	}

	if authzModel.PolicyStore != nil {
		input.PolicyStoreKind = authzModel.PolicyStore.Kind
		input.PolicyStoreID = authzModel.PolicyStore.ID
	}
	// Default policy store kind to "ledger" when not specified.
	if len(input.PolicyStoreKind) == 0 {
		input.PolicyStoreKind = LedgerKind
	}

	if authzModel.Principal != nil {
		input.HasPrincipal = true
		input.PrincipalID = authzModel.Principal.ID
		input.PrincipalType = authzModel.Principal.Type
	}

	if evaluation.Subject != nil {
		input.SubjectID = evaluation.Subject.ID
		input.SubjectType = evaluation.Subject.Type
		input.SubjectProperties = evaluation.Subject.Properties
	}

	if evaluation.Resource != nil {
		input.ResourceID = evaluation.Resource.ID
		input.ResourceType = evaluation.Resource.Type
		input.ResourceProperties = evaluation.Resource.Properties
	}

	if evaluation.Action != nil {
		input.ActionName = evaluation.Action.Name
		input.ActionProperties = evaluation.Action.Properties
	}

	return input
}
