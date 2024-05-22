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

package policies

import (
	"fmt"
	"regexp"

	_ "embed"

	aztext "github.com/permguard/permguard/pkg/extensions/text"
)

// A resource is uniquely identified with an UURString (Applicative Resource Name) which looks like uur:581616507495:default:hr-app:time-management:person/*.
// REF: https://www.permguard.com/docs/accounts/schemas/resources/.

const (
	uurFormatString    = "uur:%s:%s:%s:%s:%s"
	actionFormatString = "%s:%s"
)

type UURString aztext.WildcardString

type UUR struct {
	account        aztext.WildcardString
	tenant         aztext.WildcardString
	schema         aztext.WildcardString
	domain         aztext.WildcardString
	resource       aztext.WildcardString
	resourceFilter aztext.WildcardString
}

// An action is an operation that can affect more than one resource in the context of one or more tenants.
// REF: https://www.permguard.com/docs/accounts/schemas/actions/.

type ActionString aztext.WildcardString

type Action struct {
	Resource aztext.WildcardString
	Action   aztext.WildcardString
}

type (
	// PolicyVersionString represents a valid policy version.
	PolicyVersionString string
	// PolicyTypeString represents a valid policy type.
	PolicyTypeString string
	// PolicyLabelString represents a valid policy label.
	PolicyLabelString string
)

const (
	PolicyV1     PolicyVersionString = "permguard1"
	PolicyLatest PolicyVersionString = PolicyV1

	PolicyACType PolicyTypeString = "AC"

	PolicyTrustIdentityType PolicyTypeString = "PTI"
)

// A Policy defines a list of policy statements that can be permited or forbidden.
// REF: https://www.permguard.com/docs/access-management/policies/.

type Policy struct {
	SyntaxVersion PolicyVersionString `json:"Syntax"`
	Type          PolicyTypeString    `json:"Type"`
}

// An Access Control Policy (AC) lists the actions that can/cannot be performed and the resourcers those actions can affect.
// REF: https://www.permguard.com/docs/access-management/policies/#access-control-policy.

type ACPolicy struct {
	Policy
	Name   PolicyLabelString   `json:"Name,omitempty"`
	Permit []ACPolicyStatement `json:"Permit,omitempty"`
	Forbid []ACPolicyStatement `json:"Forbid,omitempty"`
}

//go:embed data/ac-policy-schema.json
var ACPolicySchema []byte

// A policy statement list actions associated to resources.
// REF: https://www.permguard.com/docs/access-management/policies/#policy-statement.

type ACPolicyStatement struct {
	Name      PolicyLabelString `json:"Name,omitempty"`
	Actions   []ActionString    `json:"Actions"`
	Resources []UURString       `json:"Resources"`
}

func isValidPattern(pattern string, s string) (bool, error) {
	regex := pattern
	matched, err := regexp.MatchString(regex, s)
	if err != nil {
		return false, err
	}
	return matched, nil
}

func findStringSubmatch(pattern string, s string) map[string]string {
	myExp := regexp.MustCompile(pattern)
	match := myExp.FindStringSubmatch(s)
	result := make(map[string]string)
	for i, name := range myExp.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}
	return result
}

func sanitizeTokenName(value string) string {
	sanitizedValue := value
	if len(value) == 0 {
		sanitizedValue = "*"
	}
	return sanitizedValue
}

func (a UURString) getRegex(version PolicyVersionString) (string, error) {
	switch version {
	case PolicyV1:
		cHyphenName := `([a-zA-Z0-9\*]+(-[a-zA-Z0-9\*]+)*)`
		cSlashHyphenName := fmt.Sprintf(`%s+(\/%s)*`, cHyphenName, cHyphenName)
		cHyphenExtendedName := `([a-zA-Z0-9\.@\*]+(-[a-zA-Z0-9\.@\*]+)*)`
		cSlashHyphenExtendedName := fmt.Sprintf(`%s+(\/%s)*`, cHyphenExtendedName, cHyphenExtendedName)
		cNumber := `\d{10,14}`
		cResourceFilterSlashHyphenName := fmt.Sprintf(`(?P<resource>%s+)(\/(?P<resourcefilter>%s))*`, cHyphenName, cSlashHyphenExtendedName)
		regex := fmt.Sprintf("^uur:(?P<account>(%s)?):(?P<tenant>(%s)?):(?P<schema>(%s)?):(?P<domain>(%s)?):(%s)?$", cNumber, cHyphenName, cHyphenName, cSlashHyphenName, cResourceFilterSlashHyphenName)
		return regex, nil
	default:
		return "", ErrPoliciesUnsupportedVersion
	}
}

func (a UURString) IsValid(version PolicyVersionString) (bool, error) {
	if len(a) == 0 {
		return false, nil
	}
	switch version {
	case PolicyV1:
		pattern, err := a.getRegex(version)
		if err != nil {
			return false, err
		}
		return isValidPattern(pattern, string(a))
	default:
		return false, ErrPoliciesUnsupportedVersion
	}
}

func (a UURString) Parse(version PolicyVersionString) (*UUR, error) {
	isValied, err := a.IsValid(version)
	if err != nil {
		return nil, err
	}
	if !isValied {
		return nil, ErrPoliciesInvalidUUR
	}
	pattern, err := a.getRegex(version)
	if err != nil {
		return nil, err
	}
	result := findStringSubmatch(pattern, string(a))
	return &UUR{
		account:        aztext.WildcardString(sanitizeTokenName(result["account"])),
		tenant:         aztext.WildcardString(sanitizeTokenName(result["tenant"])),
		schema:         aztext.WildcardString(sanitizeTokenName(result["schema"])),
		domain:         aztext.WildcardString(sanitizeTokenName(result["domain"])),
		resource:       aztext.WildcardString(sanitizeTokenName(result["resource"])),
		resourceFilter: aztext.WildcardString(sanitizeTokenName(result["resourcefilter"])),
	}, nil
}

func (a ActionString) getRegex(version PolicyVersionString) (string, error) {
	switch version {
	case PolicyV1:
		cHyphenName := `([a-zA-Z0-9\*]+(-[a-zA-Z0-9\*]+)*)`
		regex := fmt.Sprintf("^(?P<resource>(%s)?):(?P<action>(%s)?)$", cHyphenName, cHyphenName)
		return regex, nil
	default:
		return "", ErrPoliciesUnsupportedVersion
	}
}

func (a ActionString) IsValid(version PolicyVersionString) (bool, error) {
	if len(a) == 0 {
		return false, nil
	}
	switch version {
	case PolicyV1:
		pattern, err := a.getRegex(version)
		if err != nil {
			return false, err
		}
		return isValidPattern(pattern, string(a))
	default:
		return false, ErrPoliciesUnsupportedVersion
	}
}

func (a ActionString) Parse(version PolicyVersionString) (*Action, error) {
	isValied, err := a.IsValid(version)
	if err != nil {
		return nil, err
	}
	if !isValied {
		return nil, ErrPoliciesInvalidUUR
	}
	pattern, err := a.getRegex(version)
	if err != nil {
		return nil, err
	}
	result := findStringSubmatch(pattern, string(a))
	return &Action{
		Resource: aztext.WildcardString(sanitizeTokenName(result["resource"])),
		Action:   aztext.WildcardString(sanitizeTokenName(result["action"])),
	}, nil
}

func (p PolicyVersionString) IsValid() bool {
	return p == PolicyV1
}

func (p PolicyTypeString) IsValid(version PolicyVersionString) (bool, error) {
	if len(p) == 0 {
		return false, nil
	}
	switch version {
	case PolicyV1:
		return p == PolicyACType || p == PolicyTrustIdentityType, nil
	default:
		return false, ErrPoliciesUnsupportedVersion
	}
}

func (p PolicyLabelString) getRegex(version PolicyVersionString) (string, error) {
	switch version {
	case PolicyV1:
		cHyphenName := `([a-zA-Z0-9\*]+(-[a-zA-Z0-9:*]+)*)`
		cSlashHyphenName := fmt.Sprintf(`%s+(\/%s)*`, cHyphenName, cHyphenName)
		regex := fmt.Sprintf("^((%s)?)$", cSlashHyphenName)
		return regex, nil
	default:
		return "", ErrPoliciesUnsupportedVersion
	}
}

func (p PolicyLabelString) IsValid(version PolicyVersionString) (bool, error) {
	if len(p) == 0 {
		return false, nil
	}
	switch version {
	case PolicyV1:
		pattern, err := p.getRegex(version)
		if err != nil {
			return false, err
		}
		return isValidPattern(pattern, string(p))
	default:
		return false, ErrPoliciesUnsupportedVersion
	}
}
