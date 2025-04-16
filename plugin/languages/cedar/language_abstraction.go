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

package cedar

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go"

	azcedarlang "github.com/permguard/permguard-ztauthstar-cedar/pkg/cedarlang"
	azauthzen "github.com/permguard/permguard-ztauthstar/pkg/authzen"
	azauthzlangtypes "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar/authstarmodels/authz/languages/types"
	azauthzlangvalidators "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar/authstarmodels/authz/languages/validators"
	azztasmanifests "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar/authstarmodels/manifests"
	azobjs "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar/authstarmodels/objects"
	azengine "github.com/permguard/permguard/pkg/authz/engines"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// CedarLanguageAbstraction is the abstraction for the cedar language.
type CedarLanguageAbstraction struct {
	objMng *azobjs.ObjectManager
}

// NewCedarLanguageAbstraction creates a new CedarLanguageAbstraction.
func NewCedarLanguageAbstraction() (*CedarLanguageAbstraction, error) {
	objMng, err := azobjs.NewObjectManager()
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to create the object manager", err)
	}
	return &CedarLanguageAbstraction{
		objMng: objMng,
	}, nil
}

// BuildManifest builds the manifest.
func (abs *CedarLanguageAbstraction) BuildManifest(manifest *azztasmanifests.Manifest, template string) (*azztasmanifests.Manifest, error) {
	return azcedarlang.BuildManifest(manifest, template, azengine.EngineName, azengine.EngineVersion, azengine.EngineDist, false)
}

// ValidateManifest validates the manifest.
func (abs *CedarLanguageAbstraction) ValidateManifest(manifest *azztasmanifests.Manifest) (bool, error) {
	return azcedarlang.ValidateManifest(manifest)
}

// GetFrontendLanguage gets fronted language.
func (abs *CedarLanguageAbstraction) GetFrontendLanguage() string {
	return azcedarlang.LanguageCedar
}

// GetFrontendLanguage gets backend language.
func (abs *CedarLanguageAbstraction) GetBackendLanguage() string {
	return azcedarlang.LanguageCedarJSON
}

// GetPolicyFileExtensions gets the policy file extensions.
func (abs *CedarLanguageAbstraction) GetPolicyFileExtensions() []string {
	return []string { azcedarlang.LanguageFileExtension }
}

// CreatePolicyBlobObjects creates multi sections policy blob objects.
func (abs *CedarLanguageAbstraction) CreatePolicyBlobObjects(manifest *azztasmanifests.Manifest, paritition, filePath string, data []byte) (*azobjs.MultiSectionsObject, error) {
	// if langSpec.GetFrontendLanguage() != azcedarlang.LanguageCedar {
	// 	return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] unsupported frontend language")
	// }

	policySet, err := cedar.NewPolicySetFromBytes(filePath, data)
	if err != nil {
		multiSecObj, err2 := azobjs.NewMultiSectionsObject(filePath, 0, nil)
		if err2 != nil {
			return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to create the multi section object", err2)
		}
		multiSecObj.AddSectionObjectWithError(0, err)
		return multiSecObj, nil
	}

	policiesMap := policySet.Map()
	multiSecObj, err := azobjs.NewMultiSectionsObject(filePath, len(policiesMap), nil)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to create the multi section object", err)
	}

	const (
		codeType   = azauthzlangtypes.ClassTypePolicy
		codeTypeID = azauthzlangtypes.ClassTypePolicyID

		langPolicyType   = azcedarlang.LanguagePolicyType
		langPolicyTypeID = azcedarlang.LanguagePolicyTypeID
	)

	lang := azcedarlang.LanguageCedarJSON
	langID := azcedarlang.LanguageCedarJSONID
	langVersion := azcedarlang.LanguageSyntaxVersion
	langVersionID := azcedarlang.LanguageSyntaxVersionID

	i := -1
	for _, policy := range policiesMap {
		i++
		var policyID string
		annPolicyID, exists := policy.Annotations()["id"]
		if !exists {
			multiSecObj.AddSectionObjectWithError(i, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] missing the policy id"))
			continue
		} else {
			policyID = string(annPolicyID)
		}
		objName := policyID
		codeID := objName

		if isValid, err := azauthzlangvalidators.ValidatePolicyName(policyID); !isValid {
			multiSecObj.AddSectionObjectWithError(i, err)
			continue
		}

		header, err := azobjs.NewObjectHeader(true, langID, langVersionID, langPolicyTypeID, codeID, codeTypeID)
		if err != nil {
			multiSecObj.AddSectionObjectWithError(i, err)
			continue
		}

		policyJSON, err := policy.MarshalJSON()
		if err != nil {
			multiSecObj.AddSectionObjectWithError(i, err)
			continue
		}

		obj, err := abs.objMng.CreateBlobObject(header, policyJSON)
		if err != nil {
			multiSecObj.AddSectionObjectWithError(i, err)
			continue
		}

		objInfo, err := abs.objMng.GetObjectInfo(obj)
		if err != nil {
			return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to get the object info", err)
		}

		multiSecObj.AddSectionObjectWithParams(obj, objInfo.GetType(), objName, codeID, codeType, lang, langVersion, langPolicyType, i)
	}

	return multiSecObj, nil
}

// CreatePolicyContentBytes creates a multi policy content bytes.
func (abs *CedarLanguageAbstraction) CreatePolicyContentBytes(manifest *azztasmanifests.Manifest, paritition string, blocks [][]byte) ([]byte, string, error) {
	var sb strings.Builder
	for i, block := range blocks {
		if i > 0 {
			sb.WriteString("\n\n")
		}
		sb.Write(block)
	}
	return []byte(sb.String()), azcedarlang.LanguageFileExtension, nil
}

// GetPolicyFileExtensions gets the policy file extensions.
func (abs *CedarLanguageAbstraction) GetSchemaFileNames() []string {
	return []string { azcedarlang.LanguageSchemaFileName }
}

// CreateSchemaBlobObjects creates multi sections schema blob objects.
func (abs *CedarLanguageAbstraction) CreateSchemaBlobObjects(manifest *azztasmanifests.Manifest, paritition string, path string, data []byte) (*azobjs.MultiSectionsObject, error) {
	// if langSpec.GetFrontendLanguage() != azcedarlang.LanguageCedar {
	// 	return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] unsupported frontend language")
	// }

	const (
		objName = azauthzlangtypes.ClassTypeSchema

		codeID     = azauthzlangtypes.ClassTypeSchema
		codeType   = azauthzlangtypes.ClassTypeSchema
		codeTypeID = azauthzlangtypes.ClassTypeSchemaID

		langSchemaType   = azcedarlang.LanguageSchemaType
		langSchemaTypeID = azcedarlang.LanguageSchemaTypeID
	)

	lang := azcedarlang.LanguageCedarJSON
	langID := azcedarlang.LanguageCedarJSONID
	langVersion := azcedarlang.LanguageSyntaxVersion
	langVersionID := azcedarlang.LanguageSyntaxVersionID

	//TODO: Implement schema validation

	multiSecObj, err := azobjs.NewMultiSectionsObject(path, 1, nil)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to create the multi section object", err)
	}
	header, err := azobjs.NewObjectHeader(true, langID, langVersionID, langSchemaTypeID, codeID, codeTypeID)
	if err != nil {
		multiSecObj.AddSectionObjectWithError(0, err)
		return multiSecObj, nil
	}

	obj, err := abs.objMng.CreateBlobObject(header, data)
	if err != nil {
		multiSecObj.AddSectionObjectWithError(0, err)
		return multiSecObj, nil
	}

	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to get the object info", err)
	}

	multiSecObj.AddSectionObjectWithParams(obj, objInfo.GetType(), objName, codeID, codeType, lang, langVersion, langSchemaType, 0)
	return multiSecObj, nil
}

// CreateSchemaContentBytes creates a schema content bytes.
func (abs *CedarLanguageAbstraction) CreateSchemaContentBytes(manifest *azztasmanifests.Manifest, paritition string, blocks []byte) ([]byte, string, error) {
	if len(blocks) == 0 {
		return nil, "", azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageSyntax, "[cedar] schema cannot be empty")
	}
	return blocks, azcedarlang.LanguageSchemaFileName, nil
}

// ConvertBytesToFrontendLanguage converts bytes to the frontend language.
func (abs *CedarLanguageAbstraction) ConvertBytesToFrontendLanguage(manifest *azztasmanifests.Manifest, paritition string, langID, langVersionID, langTypeID uint32, content []byte) ([]byte, error) {
	// if azcedarlang.LanguageCedarJSONID != langID {
	// 	return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] invalid backend language")
	// }
	// if azcedarlang.LanguageSyntaxVersionID != langVersionID {
	// 	return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] invalid backend language version")
	// }
	var frontendContent []byte
	switch langTypeID {
	case azcedarlang.LanguagePolicyTypeID:
		var cedarPolicy cedar.Policy
		err := cedarPolicy.UnmarshalJSON(content)
		if err != nil {
			return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageSyntax, "[cedar] invalid policy syntax", err)
		}
		frontendContent = cedarPolicy.MarshalCedar()
	case azcedarlang.LanguageSchemaTypeID:
		frontendContent = content
	default:
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageSyntax, "[cedar] invalid syntax")
	}
	return frontendContent, nil
}

// AuthorizationCheck checks the authorization.
func (abs *CedarLanguageAbstraction) AuthorizationCheck(manifest *azztasmanifests.Manifest, paritition string, contextID string, policyStore *azauthzen.PolicyStore, authzCtx *azauthzen.AuthorizationModel) (*azauthzen.AuthorizationDecision, error) {
	// Creates a new policy set.
	ps := cedar.NewPolicySet()
	for _, policy := range policyStore.GetPolicies() {
		objInfo := policy.GetObjectInfo()
		policyBytes := objInfo.GetInstance().([]byte)
		var policy cedar.Policy
		if err := policy.UnmarshalJSON(policyBytes); err != nil {
			return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageSyntax, "[cedar] policy could not be unmarshalled", err)
		}
		codeID := objInfo.GetHeader().GetCodeID()
		ps.Add(cedar.PolicyID(codeID), &policy)
	}

	// Extract the subject from the authorization context.
	subject := authzCtx.GetSubject()
	subjectID := subject.GetID()
	if len(strings.TrimSpace(subjectID)) == 0 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the subject id")
	}
	subjectKind := subject.GetType()
	pmgSubjectKind, err := createPermguardSubjectKind(subjectKind)
	if err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the subject type")
	}
	subjectProperties, err := createEntityAttribJSON(pmgSubjectKind, subjectID, subject.GetProperties())
	if err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the subject properties")
	}

	// Extract the resource from the authorization context.
	resource := authzCtx.GetResource()
	resourceType := resource.GetType()
	if len(strings.TrimSpace(resourceType)) == 0 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the resource type")
	}
	resourceID := resource.GetID()
	if len(strings.TrimSpace(resourceID)) == 0 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the resource id")
	}
	resourceProperties, err := createEntityAttribJSON(resourceType, resourceID, resource.GetProperties())
	if err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the resource properties")
	}

	// Extract the action from the authorization context.
	action := authzCtx.GetAction()
	actionID := action.GetID()
	actiondIndex := strings.LastIndex(actionID, "::")
	if actiondIndex == -1 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for an invalid action format")
	}
	actionType := actionID[:actiondIndex]
	if len(strings.TrimSpace(actionType)) == 0 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the action type")
	}
	actionID = actionID[actiondIndex+len("::"):]
	if len(strings.TrimSpace(actionID)) == 0 {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the action id")
	}
	actionProperties, err := createEntityAttribJSON(actionType, actionID, action.GetProperties())
	if err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the action properties")
	}

	// Extract the context from the authorization context.
	context := cedar.RecordMap{}
	contextRecord := cedar.NewRecord(context)
	jsonContext, err := json.Marshal(authzCtx.GetContext())
	if err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the context")
	}
	if err := contextRecord.UnmarshalJSON(jsonContext); err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the context")
	}
	hasIllegalKey := false
	contextRecord.Iterate(func(key cedar.String, val cedar.Value) bool {
		keyStr := key.String()
		isValid, _ := verifyKey(keyStr)
		if !isValid {
			hasIllegalKey = true
			return false
		}
		return true
	})
	if hasIllegalKey {
		errMsg := fmt.Sprintf("[cedar] bad request for an invalid context key, key %s is reserved by permguard and cannot be used", actionID)
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, errMsg)
	}

	// Build the entities.
	authzEntities := authzCtx.GetEntities()
	authzEntitiesItems := authzEntities.GetItems()
	if _, err := verifyUIDTypeFromEntityMap(authzEntitiesItems); err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the entities")
	}
	authzEntitiesItems = append(authzEntitiesItems, subjectProperties)
	authzEntitiesItems = append(authzEntitiesItems, actionProperties)
	authzEntitiesItems = append(authzEntitiesItems, resourceProperties)
	jsonEntities, err := json.Marshal(authzEntitiesItems)
	if err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the entities")
	}
	var entities cedar.EntityMap
	if err := json.Unmarshal(jsonEntities, &entities); err != nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguangeSemantic, "[cedar] bad request for the entities")
	}

	// Create the request.
	req := cedar.Request{
		Principal: cedar.NewEntityUID(cedar.EntityType(pmgSubjectKind), cedar.String(subjectID)),
		Action:    cedar.NewEntityUID(cedar.EntityType(actionType), cedar.String(actionID)),
		Resource:  cedar.NewEntityUID(cedar.EntityType(resourceType), cedar.String(resourceID)),
		Context:   contextRecord,
	}

	ok, _ := ps.IsAuthorized(entities, req)
	var adminError, userError *azauthzen.AuthorizationError
	if !ok {
		adminError, userError = createAuthorizationErrors(azauthzen.AuthzErrForbiddenCode, azauthzen.AuthzErrForbiddenMessage, azauthzen.AuthzErrForbiddenMessage)
	}
	// Take the decision.
	authzDecision, err := azauthzen.NewAuthorizationDecision(contextID, bool(ok), adminError, userError)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to create the authorization decision", err)
	}
	return authzDecision, nil
}
