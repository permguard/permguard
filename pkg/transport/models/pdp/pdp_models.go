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

package pdp

// PolicyStore is the location where policies are maintained.
type PolicyStore struct {
	Type    string `json:"type,omitempty"`
	ID      string `json:"id,omitempty" validate:"required"`
	Version string `json:"version,omitempty"`
}

// Principal represents the entity making the request.
type Principal struct {
	Type          string `json:"type,omitempty"`
	ID            string `json:"id,omitempty" validate:"required"`
	Source        string `json:"source,omitempty"`
	IdentityToken string `json:"identity_token,omitempty"`
	AccessToken   string `json:"access_token,omitempty"`
}

// Entities represent the entities provided in the context for the authorization decision.
type Entities struct {
	Schema string           `json:"schema,omitempty" validate:"required"`
	Items  []map[string]any `json:"items,omitempty" validate:"required"`
}

// Subject is the entity on which the authorization decision is made.
type Subject struct {
	Type       string         `json:"type,omitempty"`
	ID         string         `json:"id,omitempty" validate:"required"`
	Source     string         `json:"source,omitempty"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Resource is the entity on which the authorization decision is made.
type Resource struct {
	Type       string         `json:"type,omitempty"`
	ID         string         `json:"id,omitempty" validate:"required"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Action is the operation on which the authorization decision is made.
type Action struct {
	Name       string         `json:"name,omitempty" validate:"required"`
	Properties map[string]any `json:"properties,omitempty"`
}

// AuthorizationCheck Request

// AuthorizationContextRequest is the input context for making the authorization decision.
type AuthorizationContextRequest struct {
	ApplicationID int64        `json:"application_id" validate:"required,gt=0"`
	PolicyStore   *PolicyStore `json:"policy_store,omitempty"`
	Principal     *Principal   `json:"principal,omitempty"`
	Entities      *Entities    `json:"entities,omitempty"`
}

// EvaluationRequest represents the request to evaluate the authorization decision.
type EvaluationRequest struct {
	Subject  *Subject       `json:"subject,omitempty"`
	Resource *Resource      `json:"resource,omitempty"`
	Action   *Action        `json:"action,omitempty"`
	Context  map[string]any `json:"context,omitempty"`
}

// AuthorizationCheckRequest represents the request to perform an authorization decision.
type AuthorizationCheckRequest struct {
	AuthorizationContext *AuthorizationContextRequest `json:"authorization_context,omitempty" validate:"required"`
	Subject              *Subject                     `json:"subject,omitempty"`
	Resource             *Resource                    `json:"resource,omitempty"`
	Action               *Action                      `json:"action,omitempty"`
	Context              map[string]any               `json:"context,omitempty"`
	Evaluations          []EvaluationRequest          `json:"evaluations,omitempty"`
}

// AuthorizationCheck Response

// ReasonResponse provides the rationale for the response.
type ReasonResponse struct {
	Code    string `json:"code,omitempty" validate:"required"`
	Message string `json:"message,omitempty" validate:"required"`
}

// ContextResponse represents the context included in the response.
type ContextResponse struct {
	ID          string          `json:"id,omitempty" validate:"required"`
	ReasonAdmin *ReasonResponse `json:"reason_admin,omitempty" validate:"required"`
	ReasonUser  *ReasonResponse `json:"reason_user,omitempty" validate:"required"`
}

// EvaluationResponse represents the result of the evaluation process.
type EvaluationResponse struct {
	Decision bool             `json:"decision,omitempty" validate:"required"`
	Context  *ContextResponse `json:"context,omitempty"`
}

// AuthorizationCheckResponse represents the outcome of the authorization decision.
type AuthorizationCheckResponse struct {
	Decision    bool                 `json:"decision,omitempty" validate:"required"`
	Context     *ContextResponse     `json:"context,omitempty"`
	Evaluations []EvaluationResponse `json:"evaluations,omitempty"`
}
