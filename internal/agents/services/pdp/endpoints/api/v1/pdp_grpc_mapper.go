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
	"google.golang.org/protobuf/types/known/structpb"

	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
)

// MapGrpcPolicyStoreToAgentPolicyStore maps the gRPC policy store to the agent policy store.
func MapGrpcPolicyStoreToAgentPolicyStore(policyStore *PolicyStore) (*azmodelspdp.PolicyStore, error) {
	if policyStore == nil {
		return nil, nil
	}
	target := &azmodelspdp.PolicyStore{}
	target.ID = policyStore.ID
	target.Kind = policyStore.Kind
	return target, nil
}

// MapAgentPolicyStoreToGrpcPolicyStore maps the agent policy store to the gRPC policy store.
func MapAgentPolicyStoreToGrpcPolicyStore(policyStore *azmodelspdp.PolicyStore) (*PolicyStore, error) {
	if policyStore == nil {
		return nil, nil
	}
	target := &PolicyStore{}
	target.ID = policyStore.ID
	target.Kind = policyStore.Kind
	return target, nil
}

// MapGrpcPrincipalToAgentPrincipal maps the gRPC principal to the agent principal.
func MapGrpcPrincipalToAgentPrincipal(principal *Principal) (*azmodelspdp.Principal, error) {
	if principal == nil {
		return nil, nil
	}
	target := &azmodelspdp.Principal{}
	target.ID = principal.ID
	target.Type = principal.Type
	if principal.Source != nil {
		target.Source = *principal.Source
	}
	if principal.IdentityToken != nil {
		target.IdentityToken = *principal.IdentityToken
	}
	if principal.AccessToken != nil {
		target.AccessToken = *principal.AccessToken
	}
	return target, nil
}

// MapAgentPrincipalToGrpcPrincipal maps the agent principal to the gRPC principal.
func MapAgentPrincipalToGrpcPrincipal(principal *azmodelspdp.Principal) (*Principal, error) {
	if principal == nil {
		return nil, nil
	}
	target := &Principal{}
	target.ID = principal.ID
	target.Type = principal.Type
	if principal.Source != "" {
		target.Source = &principal.Source
	}
	if principal.IdentityToken != "" {
		target.IdentityToken = &principal.IdentityToken
	}
	if principal.AccessToken != "" {
		target.AccessToken = &principal.AccessToken
	}
	return target, nil
}

// MapGrpcEntitiesToAgentEntities maps the gRPC entities to the agent entities.
func MapGrpcEntitiesToAgentEntities(entities *Entities) (*azmodelspdp.Entities, error) {
	if entities == nil {
		return nil, nil
	}
	target := &azmodelspdp.Entities{}
	target.Schema = entities.Schema
	if entities.Items != nil {
		items := []map[string]any{}
		for _, item := range entities.Items {
			items = append(items, item.AsMap())
		}
		target.Items = items
	}
	return target, nil
}

// MapAgentEntitiesToGrpcEntities maps the agent entities to the gRPC entities.
func MapAgentEntitiesToGrpcEntities(entities *azmodelspdp.Entities) (*Entities, error) {
	if entities == nil {
		return nil, nil
	}
	target := &Entities{}
	target.Schema = entities.Schema
	if entities.Items != nil {
		items := []*structpb.Struct{}
		for _, item := range entities.Items {
			data, err := structpb.NewStruct(item)
			if err != nil {
				return nil, err
			}
			items = append(items, data)
		}
		target.Items = items
	}
	return target, nil
}

// MapGrpcSubjectToAgentSubject maps the gRPC subject to the agent subject.
func MapGrpcSubjectToAgentSubject(subject *Subject) (*azmodelspdp.Subject, error) {
	if subject == nil {
		return nil, nil
	}
	target := &azmodelspdp.Subject{}
	target.ID = subject.ID
	target.Type = subject.Type
	if subject.Source != nil {
		target.Source = *subject.Source
	}
	if subject.Properties != nil {
		target.Properties = subject.Properties.AsMap()
	}
	return target, nil
}

// MapAgentSubjectToGrpcSubject maps the agent subject to the gRPC subject.
func MapAgentSubjectToGrpcSubject(subject *azmodelspdp.Subject) (*Subject, error) {
	if subject == nil {
		return nil, nil
	}
	target := &Subject{}
	target.ID = subject.ID
	target.Type = subject.Type
	if subject.Source != "" {
		target.Source = &subject.Source
	}
	if subject.Properties != nil {
		data, err := structpb.NewStruct(subject.Properties)
		if err != nil {
			return nil, err
		}
		target.Properties = data
	}
	return target, nil
}

// MapGrpcResourceToAgentResource maps the gRPC resource to the agent resource.
func MapGrpcResourceToAgentResource(resource *Resource) (*azmodelspdp.Resource, error) {
	if resource == nil {
		return nil, nil
	}
	target := &azmodelspdp.Resource{}
	target.ID = resource.ID
	target.Type = resource.Type
	if resource.Properties != nil {
		target.Properties = resource.Properties.AsMap()
	}
	return target, nil
}

// MapAgentResourceToGrpcResource maps the agent resource to the gRPC resource.
func MapAgentResourceToGrpcResource(resource *azmodelspdp.Resource) (*Resource, error) {
	if resource == nil {
		return nil, nil
	}
	target := &Resource{}
	target.ID = resource.ID
	target.Type = resource.Type
	if resource.Properties != nil {
		data, err := structpb.NewStruct(resource.Properties)
		if err != nil {
			return nil, err
		}
		target.Properties = data
	}
	return target, nil
}

// MapGrpcActionToAgentAction maps the gRPC action to the agent action.
func MapGrpcActionToAgentAction(action *Action) (*azmodelspdp.Action, error) {
	if action == nil {
		return nil, nil
	}
	target := &azmodelspdp.Action{}
	target.Name = action.Name
	if action.Properties != nil {
		target.Properties = action.Properties.AsMap()
	}
	return target, nil
}

// MapAgentActionToGrpcAction maps the agent action to the gRPC action.
func MapAgentActionToGrpcAction(action *azmodelspdp.Action) (*Action, error) {
	if action == nil {
		return nil, nil
	}
	target := &Action{}
	target.Name = action.Name
	if action.Properties != nil {
		data, err := structpb.NewStruct(action.Properties)
		if err != nil {
			return nil, err
		}
		target.Properties = data
	}
	return target, nil
}

// MapGrpcEvaluationRequestToAgentEvaluationRequest maps the gRPC evaluation request to the agent evaluation request.
func MapGrpcEvaluationRequestToAgentEvaluationRequest(evaluationRequest *EvaluationRequest) (*azmodelspdp.EvaluationRequest, error) {
	if evaluationRequest == nil {
		return nil, nil
	}
	target := &azmodelspdp.EvaluationRequest{}
	if evaluationRequest.RequestID != nil && len(*evaluationRequest.RequestID) > 0 {
		target.RequestID = *evaluationRequest.RequestID
	}
	if evaluationRequest.Subject != nil {
		subject, err := MapGrpcSubjectToAgentSubject(evaluationRequest.Subject)
		if err != nil {
			return nil, err
		}
		target.Subject = subject
	}
	if evaluationRequest.Resource != nil {
		resource, err := MapGrpcResourceToAgentResource(evaluationRequest.Resource)
		if err != nil {
			return nil, err
		}
		target.Resource = resource
	}
	if evaluationRequest.Action != nil {
		action, err := MapGrpcActionToAgentAction(evaluationRequest.Action)
		if err != nil {
			return nil, err
		}
		target.Action = action
	}
	if evaluationRequest.Context != nil {
		target.Context = evaluationRequest.Context.AsMap()
	}
	return target, nil
}

// MapAgentEvaluationRequestToGrpcEvaluationRequest maps the agent evaluation request to the gRPC evaluation request.
func MapAgentEvaluationRequestToGrpcEvaluationRequest(evaluationRequest *azmodelspdp.EvaluationRequest) (*EvaluationRequest, error) {
	if evaluationRequest == nil {
		return nil, nil
	}
	target := &EvaluationRequest{}
	target.RequestID = &evaluationRequest.RequestID
	if evaluationRequest.Subject != nil {
		subject, err := MapAgentSubjectToGrpcSubject(evaluationRequest.Subject)
		if err != nil {
			return nil, err
		}
		target.Subject = subject
	}
	if evaluationRequest.Resource != nil {
		resource, err := MapAgentResourceToGrpcResource(evaluationRequest.Resource)
		if err != nil {
			return nil, err
		}
		target.Resource = resource
	}
	if evaluationRequest.Action != nil {
		action, err := MapAgentActionToGrpcAction(evaluationRequest.Action)
		if err != nil {
			return nil, err
		}
		target.Action = action
	}
	if evaluationRequest.Context != nil {
		data, err := structpb.NewStruct(evaluationRequest.Context)
		if err != nil {
			return nil, err
		}
		target.Context = data
	}
	return target, nil
}

// MapGrpcAuthorizationModelRequestToAgentAuthorizationModelRequest maps the gRPC authorization context request to the agent authorization context request.
func MapGrpcAuthorizationModelRequestToAgentAuthorizationModelRequest(request *AuthorizationModelRequest) (*azmodelspdp.AuthorizationModelRequest, error) {
	req := &azmodelspdp.AuthorizationModelRequest{}
	req.ZoneID = request.ZoneID
	if request.PolicyStore != nil {
		policyStore, err := MapGrpcPolicyStoreToAgentPolicyStore(request.PolicyStore)
		if err != nil {
			return nil, err
		}
		req.PolicyStore = policyStore
	}
	if request.Principal != nil {
		principal, err := MapGrpcPrincipalToAgentPrincipal(request.Principal)
		if err != nil {
			return nil, err
		}
		req.Principal = principal
	}
	if request.Entities != nil {
		entities, err := MapGrpcEntitiesToAgentEntities(request.Entities)
		if err != nil {
			return nil, err
		}
		req.Entities = entities
	}
	return req, nil
}

// MapAgentAuthorizationModelRequestToGrpcAuthorizationModelRequest maps the agent authorization context request to the gRPC authorization context request.
func MapAgentAuthorizationModelRequestToGrpcAuthorizationModelRequest(request *azmodelspdp.AuthorizationModelRequest) (*AuthorizationModelRequest, error) {
	req := &AuthorizationModelRequest{}
	req.ZoneID = request.ZoneID
	if request.PolicyStore != nil {
		policyStore, err := MapAgentPolicyStoreToGrpcPolicyStore(request.PolicyStore)
		if err != nil {
			return nil, err
		}
		req.PolicyStore = policyStore
	}
	if request.Principal != nil {
		principal, err := MapAgentPrincipalToGrpcPrincipal(request.Principal)
		if err != nil {
			return nil, err
		}
		req.Principal = principal
	}
	if request.Entities != nil {
		entities, err := MapAgentEntitiesToGrpcEntities(request.Entities)
		if err != nil {
			return nil, err
		}
		req.Entities = entities
	}
	return req, nil
}

// MapGrpcAuthorizationCheckRequestToAgentAuthorizationCheckRequest maps the gRPC authorization check request to the agent authorization check request.
func MapGrpcAuthorizationCheckRequestToAgentAuthorizationCheckRequest(request *AuthorizationCheckRequest) (*azmodelspdp.AuthorizationCheckWithDefaultsRequest, error) {
	if request == nil {
		return nil, nil
	}
	req := &azmodelspdp.AuthorizationCheckWithDefaultsRequest{}
	if request.RequestID != nil {
		req.RequestID = *request.RequestID
	} else {
		req.RequestID = ""
	}
	if request.AuthorizationModel != nil {
		AuthorizationModel, err := MapGrpcAuthorizationModelRequestToAgentAuthorizationModelRequest(request.AuthorizationModel)
		if err != nil {
			return nil, err
		}
		req.AuthorizationModel = AuthorizationModel
	}
	if request.Subject != nil {
		subject, err := MapGrpcSubjectToAgentSubject(request.Subject)
		if err != nil {
			return nil, err
		}
		req.Subject = subject
	} else {
		req.Subject = &azmodelspdp.Subject{}
	}
	if request.Resource != nil {
		resource, err := MapGrpcResourceToAgentResource(request.Resource)
		if err != nil {
			return nil, err
		}
		req.Resource = resource
	} else {
		req.Resource = &azmodelspdp.Resource{}
	}
	if request.Action != nil {
		action, err := MapGrpcActionToAgentAction(request.Action)
		if err != nil {
			return nil, err
		}
		req.Action = action
	} else {
		req.Action = &azmodelspdp.Action{}
	}
	if request.Context != nil {
		req.Context = request.Context.AsMap()
	} else {
		req.Context = map[string]any{}
	}
	if request.Evaluations != nil {
		evaluations := []azmodelspdp.EvaluationRequest{}
		for _, evaluationRequest := range request.Evaluations {
			evaluation, err := MapGrpcEvaluationRequestToAgentEvaluationRequest(evaluationRequest)
			if len(evaluation.RequestID) == 0 {
				evaluation.RequestID = req.RequestID
			}
			if err != nil {
				return nil, err
			}
			evaluations = append(evaluations, *evaluation)
		}
		req.Evaluations = evaluations
	} else {
		req.Evaluations = []azmodelspdp.EvaluationRequest{}
	}
	return req, nil
}

// MapAgentAuthorizationCheckRequestToGrpcAuthorizationCheckRequest maps the agent authorization check request to the gRPC authorization check request.
func MapAgentAuthorizationCheckRequestToGrpcAuthorizationCheckRequest(request *azmodelspdp.AuthorizationCheckWithDefaultsRequest) (*AuthorizationCheckRequest, error) {
	if request == nil {
		return nil, nil
	}
	req := &AuthorizationCheckRequest{}
	if request.AuthorizationModel != nil {
		AuthorizationModel, err := MapAgentAuthorizationModelRequestToGrpcAuthorizationModelRequest(request.AuthorizationModel)
		if err != nil {
			return nil, err
		}
		req.AuthorizationModel = AuthorizationModel
	}
	if len(request.RequestID) > 0 {
		req.RequestID = &request.RequestID
	} else {
		reqID := ""
		req.RequestID = &reqID
	}
	if request.Subject != nil {
		subject, err := MapAgentSubjectToGrpcSubject(request.Subject)
		if err != nil {
			return nil, err
		}
		req.Subject = subject
	}
	if request.Resource != nil {
		resource, err := MapAgentResourceToGrpcResource(request.Resource)
		if err != nil {
			return nil, err
		}
		req.Resource = resource
	}
	if request.Action != nil {
		action, err := MapAgentActionToGrpcAction(request.Action)
		if err != nil {
			return nil, err
		}
		req.Action = action
	}
	if request.Context != nil {
		data, err := structpb.NewStruct(request.Context)
		if err != nil {
			return nil, err
		}
		req.Context = data
	}
	if request.Evaluations != nil {
		evaluations := []*EvaluationRequest{}
		for _, evaluationRequest := range request.Evaluations {
			evaluation, err := MapAgentEvaluationRequestToGrpcEvaluationRequest(&evaluationRequest)
			if err != nil {
				return nil, err
			}
			if evaluation.RequestID == nil {
				evaluation.RequestID = &request.RequestID
			}
			evaluations = append(evaluations, evaluation)
		}
		req.Evaluations = evaluations
	}
	return req, nil
}

// MapGrpcReasonResponseToAgentReasonResponse maps the gRPC reason response to the agent reason response.
func MapGrpcReasonResponseToAgentReasonResponse(reasonResponse *ReasonResponse) (*azmodelspdp.ReasonResponse, error) {
	if reasonResponse == nil {
		return nil, nil
	}
	target := &azmodelspdp.ReasonResponse{}
	target.Code = reasonResponse.Code
	target.Message = reasonResponse.Message
	return target, nil
}

// MapAgentReasonResponseToGrpcReasonResponse maps the agent reason response to the gRPC reason response.
func MapAgentReasonResponseToGrpcReasonResponse(reasonResponse *azmodelspdp.ReasonResponse) (*ReasonResponse, error) {
	if reasonResponse == nil {
		return nil, nil
	}
	target := &ReasonResponse{}
	target.Code = reasonResponse.Code
	target.Message = reasonResponse.Message
	return target, nil
}

// MapGrpcContextResponseToAgentContextResponse maps the gRPC context response to the agent context response.
func MapGrpcContextResponseToAgentContextResponse(contextResponse *ContextResponse) (*azmodelspdp.ContextResponse, error) {
	if contextResponse == nil {
		return nil, nil
	}
	target := &azmodelspdp.ContextResponse{}
	target.ID = contextResponse.ID
	if contextResponse.ReasonAdmin != nil {
		reasonAdmin, err := MapGrpcReasonResponseToAgentReasonResponse(contextResponse.ReasonAdmin)
		if err != nil {
			return nil, err
		}
		target.ReasonAdmin = reasonAdmin
	}
	if contextResponse.ReasonUser != nil {
		reasonUser, err := MapGrpcReasonResponseToAgentReasonResponse(contextResponse.ReasonUser)
		if err != nil {
			return nil, err
		}
		target.ReasonUser = reasonUser
	}
	return target, nil
}

// MapAgentContextResponseToGrpcContextResponse maps the agent context response to the gRPC context response.
func MapAgentContextResponseToGrpcContextResponse(contextResponse *azmodelspdp.ContextResponse) (*ContextResponse, error) {
	if contextResponse == nil {
		return nil, nil
	}
	target := &ContextResponse{}
	target.ID = contextResponse.ID
	if contextResponse.ReasonAdmin != nil {
		reasonAdmin, err := MapAgentReasonResponseToGrpcReasonResponse(contextResponse.ReasonAdmin)
		if err != nil {
			return nil, err
		}
		target.ReasonAdmin = reasonAdmin
	}
	if contextResponse.ReasonUser != nil {
		reasonUser, err := MapAgentReasonResponseToGrpcReasonResponse(contextResponse.ReasonUser)
		if err != nil {
			return nil, err
		}
		target.ReasonUser = reasonUser
	}
	return target, nil
}

// MapGrpcEvaluationResponseToAgentEvaluationResponse maps the gRPC evaluation response to the agent evaluation response.
func MapGrpcEvaluationResponseToAgentEvaluationResponse(evaluationResponse *EvaluationResponse) (*azmodelspdp.EvaluationResponse, error) {
	if evaluationResponse == nil {
		return nil, nil
	}
	target := &azmodelspdp.EvaluationResponse{}
	target.Decision = evaluationResponse.Decision
	if evaluationResponse.RequestID != nil {
		target.RequestID = *evaluationResponse.RequestID
	} else {
		target.RequestID = ""
	}
	if evaluationResponse.Context != nil {
		context, err := MapGrpcContextResponseToAgentContextResponse(evaluationResponse.Context)
		if err != nil {
			return nil, err
		}
		target.Context = context
	}
	return target, nil
}

// MapAgentEvaluationResponseToGrpcEvaluationResponse maps the agent evaluation response to the gRPC evaluation response.
func MapAgentEvaluationResponseToGrpcEvaluationResponse(evaluationResponse *azmodelspdp.EvaluationResponse) (*EvaluationResponse, error) {
	if evaluationResponse == nil {
		return nil, nil
	}
	target := &EvaluationResponse{}
	target.Decision = evaluationResponse.Decision
	target.RequestID = &evaluationResponse.RequestID
	if evaluationResponse.Context != nil {
		context, err := MapAgentContextResponseToGrpcContextResponse(evaluationResponse.Context)
		if err != nil {
			return nil, err
		}
		target.Context = context
	}
	return target, nil
}

// MapAgentAuthorizationCheckResponseToGrpcAuthorizationCheckResponse maps the agent authorization check response to the gRPC authorization check response.
func MapAgentAuthorizationCheckResponseToGrpcAuthorizationCheckResponse(response *azmodelspdp.AuthorizationCheckResponse) (*AuthorizationCheckResponse, error) {
	if response == nil {
		return nil, nil
	}
	target := &AuthorizationCheckResponse{}
	target.RequestID = &response.RequestID
	target.Decision = response.Decision
	if response.Context != nil {
		context, err := MapAgentContextResponseToGrpcContextResponse(response.Context)
		if err != nil {
			return nil, err
		}
		target.Context = context
	}
	if response.Evaluations != nil {
		evaluations := []*EvaluationResponse{}
		for _, evaluationResponse := range response.Evaluations {
			evaluation, err := MapAgentEvaluationResponseToGrpcEvaluationResponse(&evaluationResponse)
			if err != nil {
				return nil, err
			}
			evaluations = append(evaluations, evaluation)
		}
		target.Evaluations = evaluations
	}
	return target, nil
}

// MapGrpcAuthorizationCheckResponseToAgentAuthorizationCheckResponse maps the gRPC authorization check response to the agent authorization check response.
func MapGrpcAuthorizationCheckResponseToAgentAuthorizationCheckResponse(response *AuthorizationCheckResponse) (*azmodelspdp.AuthorizationCheckResponse, error) {
	if response == nil {
		return nil, nil
	}
	target := &azmodelspdp.AuthorizationCheckResponse{}
	target.Decision = response.Decision
	if response.RequestID != nil {
		target.RequestID = *response.RequestID
	} else {
		target.RequestID = ""
	}
	if response.Context != nil {
		context, err := MapGrpcContextResponseToAgentContextResponse(response.Context)
		if err != nil {
			return nil, err
		}
		target.Context = context
	}
	if response.Evaluations != nil {
		evaluations := []azmodelspdp.EvaluationResponse{}
		for _, evaluationResponse := range response.Evaluations {
			evaluation, err := MapGrpcEvaluationResponseToAgentEvaluationResponse(evaluationResponse)
			if err != nil {
				return nil, err
			}
			evaluations = append(evaluations, *evaluation)
		}
		target.Evaluations = evaluations
	}
	return target, nil
}
