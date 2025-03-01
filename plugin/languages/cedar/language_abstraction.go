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

	azlangtypes "github.com/permguard/permguard-abs-language/pkg/languages/types"
	azlangvalidators "github.com/permguard/permguard-abs-language/pkg/languages/validators"
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	azauthz "github.com/permguard/permguard/pkg/authorization"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlang "github.com/permguard/permguard/pkg/languages"
)

const (
	// LanguageName specifies the canonical name of the Cedar language.
	LanguageName = "cedar"

	// LanguageCedar represents the unique identifier for the Cedar language.
	LanguageCedar = "cedar"
	// LanguageCedarID represents the unique identifier for the Cedar language.
	LanguageCedarID = uint32(1)

	// LanguageCedarJSON represents the unique identifier for the JSON-based Cedar language.
	LanguageCedarJSON = "cedar-json"
	// LanguageCedarJSONID represents the unique identifier for the JSON-based Cedar language.
	LanguageCedarJSONID = uint32(2)

	// LanguageSyntaxVersion defines the latest syntax version used by the Cedar language.
	LanguageSyntaxVersion = "*"
	// LanguageSyntaxVersionID defines the latest syntax version ID used by the Cedar language.
	LanguageSyntaxVersionID = uint32(0)
	// LanguageSchemaType specifies the schema type for Cedar language.
	LanguageSchemaType = "schema"
	// LanguageSchemaTypeID specifies the schema type ID for Cedar language.
	LanguageSchemaTypeID = uint32(1)
	// LanguagePolicyType specifies the policy type for Cedar language.
	LanguagePolicyType = "policy"
	// LanguagePolicyTypeID specifies the policy type ID for Cedar language.
	LanguagePolicyTypeID = uint32(2)

	// LanguageFileExtension specifies the standard file extension for Cedar language files.
	LanguageFileExtension = ".cedar"
	// LanguageSchemaFileName defines the default filename for the schema definition associated with Cedar.
	LanguageSchemaFileName = "schema.json"
)

// CedarLanguageAbstraction is the abstraction for the cedar language.
type CedarLanguageAbstraction struct {
	objMng *azlangobjs.ObjectManager
}

// NewCedarLanguageAbstraction creates a new CedarLanguageAbstraction.
func NewCedarLanguageAbstraction() (*CedarLanguageAbstraction, error) {
	objMng, err := azlangobjs.NewObjectManager()
	if err != nil {
		return nil, err
	}

	return &CedarLanguageAbstraction{
		objMng: objMng,
	}, nil
}

// GetLanguageSpecification returns the specification for the language.
func (abs *CedarLanguageAbstraction) GetLanguageSpecification() azlang.LanguageSpecification {
	return &CedarLanguageSpecification{
		language:                      LanguageName,
		languageVersion:               LanguageSyntaxVersion,
		languageVersionID:             LanguageSyntaxVersionID,
		frontendLanguage:              LanguageCedar,
		frontendLanguageID:            LanguageCedarID,
		backendLanguage:               LanguageCedarJSON,
		backendLanguageID:             LanguageCedarJSONID,
		supportedPolicyFileExtensions: []string{LanguageFileExtension},
		supportedSchemaFileNames:      []string{LanguageSchemaFileName},
	}
}

// ReadObjectContentBytes reads the object content bytes.
func (abs *CedarLanguageAbstraction) ReadObjectContentBytes(obj *azlangobjs.Object) (uint32, []byte, error) {
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return 0, nil, err
	}
	objHeader := objInfo.GetHeader()
	if !objHeader.IsNativeLanguage() {
		return 0, nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrObjects, "object is not in native language")
	}
	instance, ok := objInfo.GetInstance().([]byte)
	if !ok {
		return 0, nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrObjects, "invalid object instance")
	}
	return objHeader.GetCodeTypeID(), instance, nil
}

// CreateCommitObject creates a commit object.
func (abs *CedarLanguageAbstraction) CreateCommitObject(commit *azlangobjs.Commit) (*azlangobjs.Object, error) {
	return abs.objMng.CreateCommitObject(commit)
}

// ConvertObjectToCommit converts an object to a commit.
func (abs *CedarLanguageAbstraction) ConvertObjectToCommit(obj *azlangobjs.Object) (*azlangobjs.Commit, error) {
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, err
	}

	value, ok := objInfo.GetInstance().(*azlangobjs.Commit)
	if !ok {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrObjects, "object is not a valid commit")
	}
	return value, nil
}

// CreateTreeObject creates a tree object.
func (abs *CedarLanguageAbstraction) CreateTreeObject(tree *azlangobjs.Tree) (*azlangobjs.Object, error) {
	return abs.objMng.CreateTreeObject(tree)
}

// ConvertObjectToTree converts an object to a tree.
func (abs *CedarLanguageAbstraction) ConvertObjectToTree(obj *azlangobjs.Object) (*azlangobjs.Tree, error) {
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, err
	}

	value, ok := objInfo.GetInstance().(*azlangobjs.Tree)
	if !ok {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrObjects, "object is not a valid tree")
	}
	return value, nil
}

// CreatePolicyBlobObjects creates multi sections policy blob objects.
func (abs *CedarLanguageAbstraction) CreatePolicyBlobObjects(filePath string, data []byte) (*azlangobjs.MultiSectionsObject, error) {
	langSpec := abs.GetLanguageSpecification()
	if langSpec.GetFrontendLanguage() != LanguageCedar {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] unsupported frontend language")
	}

	policySet, err := cedar.NewPolicySetFromBytes(filePath, data)
	if err != nil {
		multiSecObj, err2 := azlangobjs.NewMultiSectionsObject(filePath, 0, nil)
		if err2 != nil {
			return nil, err2
		}
		multiSecObj.AddSectionObjectWithError(0, err)
		return multiSecObj, nil
	}

	policiesMap := policySet.Map()
	multiSecObj, err := azlangobjs.NewMultiSectionsObject(filePath, len(policiesMap), nil)
	if err != nil {
		return nil, err
	}

	const (
		codeType   = azlangtypes.ClassTypePolicy
		codeTypeID = azlangtypes.ClassTypePolicyID

		langPolicyType   = LanguagePolicyType
		langPolicyTypeID = LanguagePolicyTypeID
	)

	lang := langSpec.GetBackendLanguage()
	langID := langSpec.GetBackendLanguageID()
	langVersion := langSpec.GetLanguageVersion()
	langVersionID := langSpec.GetLanguageVersionID()

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

		if isValid, err := azlangvalidators.ValidatePolicyName(policyID); !isValid {
			multiSecObj.AddSectionObjectWithError(i, err)
			continue
		}

		header, err := azlangobjs.NewObjectHeader(true, langID, langVersionID, langPolicyTypeID, codeID, codeTypeID)
		if err != nil {
			multiSecObj.AddSectionObjectWithError(i, err)
			continue
		}

		policyJson, err := policy.MarshalJSON()
		if err != nil {
			multiSecObj.AddSectionObjectWithError(i, err)
			continue
		}

		obj, err := abs.objMng.CreateBlobObject(header, policyJson)
		if err != nil {
			multiSecObj.AddSectionObjectWithError(i, err)
			continue
		}

		objInfo, err := abs.objMng.GetObjectInfo(obj)
		if err != nil {
			return nil, err
		}

		multiSecObj.AddSectionObjectWithParams(obj, objInfo.GetType(), objName, codeID, codeType, lang, langVersion, langPolicyType, i)
	}

	return multiSecObj, nil
}

// CreateMultiPolicyContentBytes creates a multi policy content bytes.
func (abs *CedarLanguageAbstraction) CreateMultiPolicyContentBytes(blocks [][]byte) ([]byte, string, error) {
	var sb strings.Builder
	for i, block := range blocks {
		if i > 0 {
			sb.WriteString("\n\n")
		}
		sb.Write(block)
	}
	return []byte(sb.String()), LanguageFileExtension, nil
}

// CreateSchemaBlobObjects creates multi sections schema blob objects.
func (abs *CedarLanguageAbstraction) CreateSchemaBlobObjects(path string, data []byte) (*azlangobjs.MultiSectionsObject, error) {
	langSpec := abs.GetLanguageSpecification()
	if langSpec.GetFrontendLanguage() != LanguageCedar {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] unsupported frontend language")
	}

	const (
		objName = azlangtypes.ClassTypeSchema

		codeID     = azlangtypes.ClassTypeSchema
		codeType   = azlangtypes.ClassTypeSchema
		codeTypeID = azlangtypes.ClassTypeSchemaID

		langSchemaType   = LanguageSchemaType
		langSchemaTypeID = LanguageSchemaTypeID
	)

	lang := langSpec.GetBackendLanguage()
	langID := langSpec.GetBackendLanguageID()
	langVersion := langSpec.GetLanguageVersion()
	langVersionID := langSpec.GetLanguageVersionID()

	//TODO: Implement schema validation

	multiSecObj, err := azlangobjs.NewMultiSectionsObject(path, 1, nil)
	header, err := azlangobjs.NewObjectHeader(true, langID, langVersionID, langSchemaTypeID, codeID, codeTypeID)
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
		return nil, err
	}

	multiSecObj.AddSectionObjectWithParams(obj, objInfo.GetType(), objName, codeID, codeType, lang, langVersion, langSchemaType, 0)
	return multiSecObj, nil
}

// CreateSchemaContentBytes creates a schema content bytes.
func (abs *CedarLanguageAbstraction) CreateSchemaContentBytes(blocks []byte) ([]byte, string, error) {
	if len(blocks) == 0 {
		return nil, "", azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageSyntax, "[cedar] schema cannot be empty")
	}
	return blocks, LanguageSchemaFileName, nil
}

// ConvertBytesToFrontendLanguage converts bytes to the frontend language.
func (abs *CedarLanguageAbstraction) ConvertBytesToFrontendLanguage(langID, langVersionID, langTypeID uint32, content []byte) ([]byte, error) {
	langSpec := abs.GetLanguageSpecification()
	if langSpec.GetBackendLanguageID() != langID {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] invalid backend language")
	}
	if langSpec.GetLanguageVersionID() != langVersionID {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] invalid backend language version")
	}
	var frontendContent []byte
	switch langTypeID {
	case LanguagePolicyTypeID:
		var cedarPolicy cedar.Policy
		err := cedarPolicy.UnmarshalJSON(content)
		if err != nil {
			return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageSyntax, "[cedar] invalid policy syntax", err)
		}
		frontendContent = cedarPolicy.MarshalCedar()
	case LanguageSchemaTypeID:
		frontendContent = content
	default:
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageSyntax, "[cedar] invalid syntax")
	}
	return frontendContent, nil
}

// AuthorizationCheck checks the authorization.
func (abs *CedarLanguageAbstraction) AuthorizationCheck(contextID string, policyStore *azauthz.PolicyStore, authzCtx *azauthz.AuthorizationModel) (*azauthz.AuthorizationDecision, error) {
	// Creates a new policy set.
	ps := cedar.NewPolicySet()
	for _, policy := range policyStore.GetPolicies() {
		objInfo := policy.GetObjectInfo()
		policyBytes := objInfo.GetInstance().([]byte)
		var policy cedar.Policy
		if err := policy.UnmarshalJSON(policyBytes); err != nil {
			return nil, err
		}
		codeID := objInfo.GetHeader().GetCodeID()
		ps.Add(cedar.PolicyID(codeID), &policy)
	}

	// Extract the subject from the authorization context.
	subject := authzCtx.GetSubject()
	subjectID := subject.GetID()
	if len(strings.TrimSpace(subjectID)) == 0 {
		errMsg := fmt.Sprintf("%s for the subject id", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}
	subjectKind := subject.GetKind()
	pmgSubjectKind, err := createPermguardSubjectKind(subjectKind)
	if err != nil {
		errMsg := fmt.Sprintf("%s for the subject type", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}
	subjectProperties, err := createEntityAttribJson(pmgSubjectKind, subjectID, subject.GetProperties())
	if err != nil {
		errMsg := fmt.Sprintf("%s for the subject properties", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}

	// Extract the resource from the authorization context.
	resource := authzCtx.GetResource()
	resourceType := resource.GetKind()
	if len(strings.TrimSpace(resourceType)) == 0 {
		errMsg := fmt.Sprintf("%s for the resource type", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}
	resourceID := resource.GetID()
	if len(strings.TrimSpace(resourceID)) == 0 {
		errMsg := fmt.Sprintf("%s for the resource id", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}
	resourceProperties, err := createEntityAttribJson(resourceType, resourceID, resource.GetProperties())
	if err != nil {
		errMsg := fmt.Sprintf("%s for the resource properties", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}

	// Extract the action from the authorization context.
	action := authzCtx.GetAction()
	actionID := action.GetID()
	actiondIndex := strings.LastIndex(actionID, "::")
	if actiondIndex == -1 {
		errMsg := fmt.Sprintf("%s for an invalid action format %s", azauthz.AuthzErrBadRequestMessage, actionID)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}
	actionType := actionID[:actiondIndex]
	if len(strings.TrimSpace(actionType)) == 0 {
		errMsg := fmt.Sprintf("%s for the action type", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}
	actionID = actionID[actiondIndex+len("::"):]
	if len(strings.TrimSpace(actionID)) == 0 {
		errMsg := fmt.Sprintf("%s for the action id", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}
	actionProperties, err := createEntityAttribJson(actionType, actionID, action.GetProperties())
	if err != nil {
		errMsg := fmt.Sprintf("%s for the action properties", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}

	// Extract the context from the authorization context.
	context := cedar.RecordMap{}
	contextRecord := cedar.NewRecord(context)
	jsonContext, err := json.Marshal(authzCtx.GetContext())
	if err != nil {
		errMsg := fmt.Sprintf("%s for the context", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}
	if err := contextRecord.UnmarshalJSON(jsonContext); err != nil {
		errMsg := fmt.Sprintf("%s for the context", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
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
		errMsg := fmt.Sprintf("%s for an invalid context key, key %s is reserved by permguard and cannot be used", azauthz.AuthzErrBadRequestMessage, actionID)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}

	// Build the entities.
	authzEntities := authzCtx.GetEntities()
	authzEntitiesItems := authzEntities.GetItems()
	if _, err := verifyUIDTypeFromEntityMap(authzEntitiesItems); err != nil {
		errMsg := fmt.Sprintf("%s for the entities", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}
	authzEntitiesItems = append(authzEntitiesItems, subjectProperties)
	authzEntitiesItems = append(authzEntitiesItems, actionProperties)
	authzEntitiesItems = append(authzEntitiesItems, resourceProperties)
	jsonEntities, err := json.Marshal(authzEntitiesItems)
	if err != nil {
		errMsg := fmt.Sprintf("%s for the entities", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}
	var entities cedar.EntityMap
	if err := json.Unmarshal(jsonEntities, &entities); err != nil {
		errMsg := fmt.Sprintf("%s for the entities", azauthz.AuthzErrBadRequestMessage)
		adminError, userError := createAuthorizationErrors(azauthz.AuthzErrBadRequestCode, errMsg, azauthz.AuthzErrBadRequestCode)
		return azauthz.NewAuthorizationDecision(contextID, false, adminError, userError)
	}

	// Create the request.
	req := cedar.Request{
		Principal: cedar.NewEntityUID(cedar.EntityType(pmgSubjectKind), cedar.String(subjectID)),
		Action:    cedar.NewEntityUID(cedar.EntityType(actionType), cedar.String(actionID)),
		Resource:  cedar.NewEntityUID(cedar.EntityType(resourceType), cedar.String(resourceID)),
		Context:   contextRecord,
	}

	ok, _ := ps.IsAuthorized(entities, req)
	var adminError, userError *azauthz.AuthorizationError
	if !ok {
		adminError, userError = createAuthorizationErrors(azauthz.AuthzErrForbiddenCode, azauthz.AuthzErrForbiddenMessage, azauthz.AuthzErrForbiddenMessage)
	}
	// Take the decision.
	authzDecision, err := azauthz.NewAuthorizationDecision(contextID, bool(ok), adminError, userError)
	if err != nil {
		return nil, err
	}
	return authzDecision, nil
}
