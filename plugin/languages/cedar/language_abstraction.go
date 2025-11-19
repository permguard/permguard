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
	"errors"
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go"

	"github.com/permguard/permguard/pkg/authz/engines"
	"github.com/permguard/permguard/ztauthstar-cedar/pkg/cedarlang"
	"github.com/permguard/permguard/ztauthstar/pkg/authzen"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/authz/languages/types"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/authz/languages/validators"
	manifests "github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/manifests"
	"github.com/permguard/permguard/ztauthstar/pkg/ztauthstar/authstarmodels/objects"
)

// CedarLanguageAbstraction is the abstraction for the cedar language.
type CedarLanguageAbstraction struct {
	objMng *objects.ObjectManager
}

// NewCedarLanguageAbstraction creates a new CedarLanguageAbstraction.
func NewCedarLanguageAbstraction() (*CedarLanguageAbstraction, error) {
	objMng, err := objects.NewObjectManager()
	if err != nil {
		return nil, errors.Join(err, errors.New("cedar: failed to create the object manager"))
	}
	return &CedarLanguageAbstraction{
		objMng: objMng,
	}, nil
}

// BuildManifest builds the manifest.
func (abs *CedarLanguageAbstraction) BuildManifest(manifest *manifests.Manifest, template string) (*manifests.Manifest, error) {
	return cedarlang.BuildManifest(manifest, template, engines.EngineName, engines.EngineVersion, engines.EngineDist, false)
}

// ValidateManifest validates the manifest.
func (abs *CedarLanguageAbstraction) ValidateManifest(manifest *manifests.Manifest) (bool, error) {
	return cedarlang.ValidateManifest(manifest)
}

// Language gets the language name
func (abs *CedarLanguageAbstraction) Language() string {
	return cedarlang.LanguageCedar
}

// LanguageID gets the language id
func (abs *CedarLanguageAbstraction) LanguageID() uint32 {
	return cedarlang.LanguageCedarID
}

// FrontendLanguage gets fronted language.
func (abs *CedarLanguageAbstraction) FrontendLanguage() string {
	return cedarlang.LanguageCedar
}

// BackendLanguage gets backend language.
func (abs *CedarLanguageAbstraction) BackendLanguage() string {
	return cedarlang.LanguageCedarJSON
}

// PolicyFileExtensions gets the policy file extensions.
func (abs *CedarLanguageAbstraction) PolicyFileExtensions() []string {
	return []string{cedarlang.LanguageFileExtension}
}

// CreatePolicyBlobObjects creates multi sections policy blob objects.
func (abs *CedarLanguageAbstraction) CreatePolicyBlobObjects(mfestLang *manifests.Language, partition string, filePath string, data []byte) (*objects.MultiSectionsObject, error) {
	if mfestLang.Name != cedarlang.LanguageCedar {
		return nil, errors.New("cedar: unsupported frontend language")
	}

	policySet, err := cedar.NewPolicySetFromBytes(filePath, data)
	if err != nil {
		multiSecObj, err2 := objects.NewMultiSectionsObject(filePath, 0, nil)
		if err2 != nil {
			return nil, errors.New("cedar: failed to create the multi section object")
		}
		multiSecObj.AddSectionObjectWithError(0, err)
		return multiSecObj, nil
	}

	policiesMap := policySet.Map()
	multiSecObj, err := objects.NewMultiSectionsObject(filePath, len(policiesMap), nil)
	if err != nil {
		return nil, errors.New("cedar: failed to create the multi section object")
	}

	const (
		codeType   = types.ClassTypePolicy
		codeTypeID = types.ClassTypePolicyID

		langPolicyType   = cedarlang.LanguagePolicyType
		langPolicyTypeID = cedarlang.LanguagePolicyTypeID
	)

	lang := cedarlang.LanguageCedarJSON
	langID := cedarlang.LanguageCedarJSONID
	langVersion := cedarlang.LanguageSyntaxVersion
	langVersionID := cedarlang.LanguageSyntaxVersionID

	i := -1
	for _, policy := range policiesMap {
		i++
		var policyID string
		annPolicyID, exists := policy.Annotations()["id"]
		if !exists {
			multiSecObj.AddSectionObjectWithError(i, errors.New("cedar: missing the policy id"))
			continue
		} else {
			policyID = string(annPolicyID)
		}
		objName := policyID
		codeID := objName

		if isValid, err := validators.ValidatePolicyName(policyID); !isValid {
			multiSecObj.AddSectionObjectWithError(i, err)
			continue
		}

		header, err := objects.NewObjectHeader(partition, true, langID, langVersionID, langPolicyTypeID, codeID, codeTypeID)
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

		objInfo, err := abs.objMng.ObjectInfo(obj)
		if err != nil {
			return nil, errors.Join(err, errors.New("cedar: failed to get the object info"))
		}

		multiSecObj.AddSectionObjectWithParams(obj, partition, objInfo.Type(), objName, codeID, codeType, lang, langVersion, langPolicyType, i)
	}

	return multiSecObj, nil
}

// CreatePolicyContentBytes creates a multi policy content bytes.
func (abs *CedarLanguageAbstraction) CreatePolicyContentBytes(mfestLang *manifests.Language, blocks [][]byte) ([]byte, string, error) {
	var sb strings.Builder
	for i, block := range blocks {
		if i > 0 {
			sb.WriteString("\n\n")
		}
		sb.Write(block)
	}
	return []byte(sb.String()), cedarlang.LanguageFileExtension, nil
}

// SchemaFileNames gets schema file names.
func (abs *CedarLanguageAbstraction) SchemaFileNames() []string {
	return []string{cedarlang.LanguageSchemaFileName}
}

// CreateSchemaBlobObjects creates multi sections schema blob objects.
func (abs *CedarLanguageAbstraction) CreateSchemaBlobObjects(mfestLang *manifests.Language, partition string, path string, data []byte) (*objects.MultiSectionsObject, error) {
	if mfestLang.Name != cedarlang.LanguageCedar {
		return nil, errors.New("cedar: unsupported frontend language")
	}

	const (
		objName = types.ClassTypeSchema

		codeID     = types.ClassTypeSchema
		codeType   = types.ClassTypeSchema
		codeTypeID = types.ClassTypeSchemaID

		langSchemaType   = cedarlang.LanguageSchemaType
		langSchemaTypeID = cedarlang.LanguageSchemaTypeID
	)

	lang := cedarlang.LanguageCedarJSON
	langID := cedarlang.LanguageCedarJSONID
	langVersion := cedarlang.LanguageSyntaxVersion
	langVersionID := cedarlang.LanguageSyntaxVersionID

	// TODO: Implement schema validation

	multiSecObj, err := objects.NewMultiSectionsObject(path, 1, nil)
	if err != nil {
		return nil, errors.Join(err, errors.New("cedar: failed to create the multi section object"))
	}
	header, err := objects.NewObjectHeader(partition, true, langID, langVersionID, langSchemaTypeID, codeID, codeTypeID)
	if err != nil {
		multiSecObj.AddSectionObjectWithError(0, err)
		return multiSecObj, nil
	}

	obj, err := abs.objMng.CreateBlobObject(header, data)
	if err != nil {
		multiSecObj.AddSectionObjectWithError(0, err)
		return multiSecObj, nil
	}

	objInfo, err := abs.objMng.ObjectInfo(obj)
	if err != nil {
		return nil, errors.Join(err, errors.New("cedar: failed to get the object info"))
	}

	multiSecObj.AddSectionObjectWithParams(obj, partition, objInfo.Type(), objName, codeID, codeType, lang, langVersion, langSchemaType, 0)
	return multiSecObj, nil
}

// CreateSchemaContentBytes creates a schema content bytes.
func (abs *CedarLanguageAbstraction) CreateSchemaContentBytes(mfestLang *manifests.Language, blocks []byte) ([]byte, string, error) {
	if len(blocks) == 0 {
		return nil, "", errors.New("cedar: schema cannot be empty")
	}
	return blocks, cedarlang.LanguageSchemaFileName, nil
}

// ConvertBytesToFrontendLanguage converts bytes to the frontend language.
func (abs *CedarLanguageAbstraction) ConvertBytesToFrontendLanguage(mfestLang *manifests.Language, langID, langVersionID, langTypeID uint32, content []byte) ([]byte, error) {
	if cedarlang.LanguageCedarJSONID != langID {
		return nil, errors.New("cedar: invalid backend language")
	}
	if cedarlang.LanguageSyntaxVersionID != langVersionID {
		return nil, errors.New("cedar: invalid backend language version")
	}
	var frontendContent []byte
	switch langTypeID {
	case cedarlang.LanguagePolicyTypeID:
		var cedarPolicy cedar.Policy
		err := cedarPolicy.UnmarshalJSON(content)
		if err != nil {
			return nil, errors.Join(err, errors.New("cedar: invalid policy syntax"))
		}
		frontendContent = cedarPolicy.MarshalCedar()
	case cedarlang.LanguageSchemaTypeID:
		frontendContent = content
	default:
		return nil, errors.New("cedar: invalid syntax")
	}
	return frontendContent, nil
}

// AuthorizationCheck checks the authorization.
func (abs *CedarLanguageAbstraction) AuthorizationCheck(mfestLang *manifests.Language, contextID string, policyStore *authzen.PolicyStore, authzCtx *authzen.AuthorizationModel) (*authzen.AuthorizationDecision, error) {
	// Creates a new policy set.
	ps := cedar.NewPolicySet()
	for _, policy := range policyStore.Policies() {
		objInfo := policy.ObjectInfo()
		policyBytes := objInfo.Instance().([]byte)
		var policy cedar.Policy
		if err := policy.UnmarshalJSON(policyBytes); err != nil {
			return nil, errors.Join(err, errors.New("cedar: policy could not be unmarshalled"))
		}
		codeID := objInfo.Header().CodeID()
		ps.Add(cedar.PolicyID(codeID), &policy)
	}

	// Extract the subject from the authorization context.
	subject := authzCtx.Subject()
	subjectID := subject.ID()
	if len(strings.TrimSpace(subjectID)) == 0 {
		return nil, errors.New("cedar: bad request for the subject id")
	}
	subjectKind := subject.Type()
	var err error
	var pmgSubjectKind string
	pmgSubjectKind, err = createPermguardSubjectKind(subjectKind)
	if err != nil {
		return nil, errors.Join(err, errors.New("cedar: bad request for the subject type"))
	}
	subjectProperties, err := createEntityAttribJSON(pmgSubjectKind, subjectID, subject.Properties())
	if err != nil {
		return nil, errors.Join(err, errors.New("cedar: bad request for the subject properties"))
	}

	// Extract the resource from the authorization context.
	resource := authzCtx.Resource()
	resourceType := resource.Type()
	if len(strings.TrimSpace(resourceType)) == 0 {
		return nil, errors.New("cedar: bad request for the resource type")
	}
	resourceID := resource.ID()
	if len(strings.TrimSpace(resourceID)) == 0 {
		return nil, errors.New("cedar: bad request for the resource id")
	}
	resourceProperties, err := createEntityAttribJSON(resourceType, resourceID, resource.Properties())
	if err != nil {
		return nil, errors.New("cedar: bad request for the resource properties")
	}

	// Extract the action from the authorization context.
	action := authzCtx.Action()
	actionID := action.ID()
	actiondIndex := strings.LastIndex(actionID, "::")
	if actiondIndex == -1 {
		return nil, errors.New("cedar: bad request for an invalid action format")
	}
	actionType := actionID[:actiondIndex]
	if len(strings.TrimSpace(actionType)) == 0 {
		return nil, errors.New("cedar: bad request for the action type")
	}
	actionID = actionID[actiondIndex+len("::"):]
	if len(strings.TrimSpace(actionID)) == 0 {
		return nil, errors.New("cedar: bad request for the action id")
	}
	actionProperties, err := createEntityAttribJSON(actionType, actionID, action.Properties())
	if err != nil {
		return nil, errors.Join(err, errors.New("cedar: bad request for the action properties"))
	}

	// Extract the context from the authorization context.
	context := cedar.RecordMap{}
	contextRecord := cedar.NewRecord(context)
	jsonContext, err := json.Marshal(authzCtx.Context())
	if err != nil {
		return nil, errors.Join(err, errors.New("cedar: bad request for the context"))
	}
	if err = contextRecord.UnmarshalJSON(jsonContext); err != nil {
		return nil, errors.Join(err, errors.New("cedar: bad request for the context"))
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
		return nil, fmt.Errorf("cedar: bad request for an invalid context key, key %s is reserved by permguard and cannot be used", actionID)
	}

	// Build the entities.
	var entities cedar.EntityMap = nil
	authzEntities := authzCtx.Entities()
	if authzEntities != nil {
		authzEntitiesItems := authzEntities.Items()
		if _, err = verifyUIDTypeFromEntityMap(authzEntitiesItems); err != nil {
			return nil, errors.Join(err, errors.New("cedar: bad request for the entities"))
		}
		authzEntitiesItems = append(authzEntitiesItems, subjectProperties)
		authzEntitiesItems = append(authzEntitiesItems, actionProperties)
		authzEntitiesItems = append(authzEntitiesItems, resourceProperties)
		jsonEntities, err2 := json.Marshal(authzEntitiesItems)
		if err2 != nil {
			return nil, errors.Join(err, errors.New("cedar: bad request for the entities"))
		}
		if err = json.Unmarshal(jsonEntities, &entities); err != nil {
			return nil, errors.Join(err, errors.New("cedar: bad request for the entities"))
		}
	}

	// Create the request.
	req := cedar.Request{
		Principal: cedar.NewEntityUID(cedar.EntityType(pmgSubjectKind), cedar.String(subjectID)),
		Action:    cedar.NewEntityUID(cedar.EntityType(actionType), cedar.String(actionID)),
		Resource:  cedar.NewEntityUID(cedar.EntityType(resourceType), cedar.String(resourceID)),
		Context:   contextRecord,
	}

	ok, _ := ps.IsAuthorized(entities, req)
	var adminError, userError *authzen.AuthorizationError
	if !ok {
		adminError, userError = createAuthorizationErrors(authzen.AuthzErrForbiddenCode, authzen.AuthzErrForbiddenMessage, authzen.AuthzErrForbiddenMessage)
	}
	// Take the decision.
	authzDecision, err := authzen.NewAuthorizationDecision(contextID, bool(ok), adminError, userError)
	if err != nil {
		return nil, errors.Join(err, errors.New("cedar: failed to create the authorization decision"))
	}
	return authzDecision, nil
}
