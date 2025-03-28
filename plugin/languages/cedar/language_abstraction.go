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

	azauthzen "github.com/permguard/permguard-ztauthstar-engine/pkg/authzen"
	azledger "github.com/permguard/permguard-ztauthstar-ledger/pkg/objects"
	azlangtypes "github.com/permguard/permguard-ztauthstar/pkg/languages/types"
	azlangvalidators "github.com/permguard/permguard-ztauthstar/pkg/languages/validators"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azlang "github.com/permguard/permguard/pkg/languages"
	azztas "github.com/permguard/permguard-ztauthstar/pkg/ztauthstar"
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
	objMng *azledger.ObjectManager
}

// NewCedarLanguageAbstraction creates a new CedarLanguageAbstraction.
func NewCedarLanguageAbstraction() (*CedarLanguageAbstraction, error) {
	objMng, err := azledger.NewObjectManager()
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to create the object manager", err)
	}

	return &CedarLanguageAbstraction{
		objMng: objMng,
	}, nil
}

// BuildManifest builds the manifest.
func (abs *CedarLanguageAbstraction) BuildManifest(manifest *azztas.Manifest, language, template string) (*azztas.Manifest, error) {
	if manifest == nil {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] manifest is nil")
	}
	return manifest, nil
}

// ValidateManifest validates the manifest.
func (cedar *CedarLanguageAbstraction) ValidateManifest(manifest *azztas.Manifest) (bool, error) {
	if manifest == nil {
		return false, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] manifest is nil")
	}
	return true, nil
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
func (abs *CedarLanguageAbstraction) ReadObjectContentBytes(obj *azledger.Object) (uint32, []byte, error) {
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return 0, nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to get the object info", err)
	}
	objHeader := objInfo.GetHeader()
	if !objHeader.IsNativeLanguage() {
		return 0, nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrObjects, "[cedar] object is not in native language")
	}
	instance, ok := objInfo.GetInstance().([]byte)
	if !ok {
		return 0, nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrObjects, "[cedar] invalid object instance")
	}
	return objHeader.GetCodeTypeID(), instance, nil
}

// CreateCommitObject creates a commit object.
func (abs *CedarLanguageAbstraction) CreateCommitObject(commit *azledger.Commit) (*azledger.Object, error) {
	return abs.objMng.CreateCommitObject(commit)
}

// ConvertObjectToCommit converts an object to a commit.
func (abs *CedarLanguageAbstraction) ConvertObjectToCommit(obj *azledger.Object) (*azledger.Commit, error) {
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to get the object info", err)
	}

	value, ok := objInfo.GetInstance().(*azledger.Commit)
	if !ok {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrObjects, "[cedar] object is not a valid commit")
	}
	return value, nil
}

// CreateTreeObject creates a tree object.
func (abs *CedarLanguageAbstraction) CreateTreeObject(tree *azledger.Tree) (*azledger.Object, error) {
	return abs.objMng.CreateTreeObject(tree)
}

// ConvertObjectToTree converts an object to a tree.
func (abs *CedarLanguageAbstraction) ConvertObjectToTree(obj *azledger.Object) (*azledger.Tree, error) {
	objInfo, err := abs.objMng.GetObjectInfo(obj)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to get the object info", err)
	}

	value, ok := objInfo.GetInstance().(*azledger.Tree)
	if !ok {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrObjects, "[cedar] object is not a valid tree")
	}
	return value, nil
}

// CreatePolicyBlobObjects creates multi sections policy blob objects.
func (abs *CedarLanguageAbstraction) CreatePolicyBlobObjects(filePath string, data []byte) (*azledger.MultiSectionsObject, error) {
	langSpec := abs.GetLanguageSpecification()
	if langSpec.GetFrontendLanguage() != LanguageCedar {
		return nil, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] unsupported frontend language")
	}

	policySet, err := cedar.NewPolicySetFromBytes(filePath, data)
	if err != nil {
		multiSecObj, err2 := azledger.NewMultiSectionsObject(filePath, 0, nil)
		if err2 != nil {
			return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to create the multi section object", err2)
		}
		multiSecObj.AddSectionObjectWithError(0, err)
		return multiSecObj, nil
	}

	policiesMap := policySet.Map()
	multiSecObj, err := azledger.NewMultiSectionsObject(filePath, len(policiesMap), nil)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to create the multi section object", err)
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

		header, err := azledger.NewObjectHeader(true, langID, langVersionID, langPolicyTypeID, codeID, codeTypeID)
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
func (abs *CedarLanguageAbstraction) CreateSchemaBlobObjects(path string, data []byte) (*azledger.MultiSectionsObject, error) {
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

	multiSecObj, err := azledger.NewMultiSectionsObject(path, 1, nil)
	if err != nil {
		return nil, azerrors.WrapHandledSysErrorWithMessage(azerrors.ErrLanguageGeneric, "[cedar] failed to create the multi section object", err)
	}
	header, err := azledger.NewObjectHeader(true, langID, langVersionID, langSchemaTypeID, codeID, codeTypeID)
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
func (abs *CedarLanguageAbstraction) AuthorizationCheck(contextID string, policyStore *azauthzen.PolicyStore, authzCtx *azauthzen.AuthorizationModel) (*azauthzen.AuthorizationDecision, error) {
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
