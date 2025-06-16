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

package objects

import (
	"errors"

	"github.com/permguard/permguard/common/pkg/extensions/copier"
)

// SectionObject represents a section object.
type SectionObject struct {
	obj             *Object
	partition       string
	otype           string
	oname           string
	codeID          string
	codeType        string
	language        string
	languageVersion string
	languageType    string
	numOfSect       int
	err             error
}

// Object returns the object.
func (s *SectionObject) Object() *Object {
	return s.obj
}

// Partition returns the partition.
func (s *SectionObject) Partition() string {
	return s.partition
}

// ObjectType returns the object type.
func (s *SectionObject) ObjectType() string {
	return s.otype
}

// ObjectName returns the object name.
func (s *SectionObject) ObjectName() string {
	return s.oname
}

// CodeID returns the code ID.
func (s *SectionObject) CodeID() string {
	return s.codeID
}

// CodeType returns the code type.
func (s *SectionObject) CodeType() string {
	return s.codeType
}

// Language returns the language.
func (s *SectionObject) Language() string {
	return s.language
}

// LanguageVersion returns the language version.
func (s *SectionObject) LanguageVersion() string {
	return s.languageVersion
}

// LanguageType returns the language type.
func (s *SectionObject) LanguageType() string {
	return s.languageType
}

// NumberOfSection returns the number section.
func (s *SectionObject) NumberOfSection() int {
	return s.numOfSect
}

// Error returns the error.
func (s *SectionObject) Error() error {
	return s.err
}

// NewSectionObject creates a new section object.
func NewSectionObject(obj *Object, partition, objType, objName, codeID, codeType, language, languageVersion, languageType string, section int, err error) (*SectionObject, error) {
	return &SectionObject{
		partition:       partition,
		obj:             obj,
		otype:           objType,
		oname:           objName,
		codeID:          codeID,
		codeType:        codeType,
		language:        language,
		languageVersion: languageVersion,
		languageType:    languageType,
		numOfSect:       section,
		err:             err,
	}, nil
}

// MultiSectionsObject represents a multi section object.
type MultiSectionsObject struct {
	path        string
	objSections []*SectionObject
	numOfSects  int
	err         error
}

// Path returns the path.
func (m *MultiSectionsObject) Path() string {
	return m.path
}

// SectionObjects returns the section objects.
func (m *MultiSectionsObject) SectionObjects() []*SectionObject {
	return copier.CopySlice(m.objSections)
}

// NumberOfSections returns the number of sections.
func (m *MultiSectionsObject) NumberOfSections() int {
	return m.numOfSects
}

// Error returns the error.
func (m *MultiSectionsObject) Error() error {
	return m.err
}

// NewMultiSectionsObject creates a new multi section object.
func NewMultiSectionsObject(path string, numOfSections int, err error) (*MultiSectionsObject, error) {
	return &MultiSectionsObject{
		path:        path,
		objSections: make([]*SectionObject, 0),
		numOfSects:  numOfSections,
		err:         err,
	}, nil
}

// AddSectionObject adds a section object.
func (m *MultiSectionsObject) AddSectionObject(obj *SectionObject) error {
	if obj == nil {
		return errors.New("object is nil")
	}
	m.objSections = append(m.objSections, obj)
	return nil
}

// AddSectionObjectWithParams adds a section object with parameters.
func (m *MultiSectionsObject) AddSectionObjectWithParams(obj *Object, partition, objType, objName, codeID, codeType, language, languageVersion, languageType string, section int) error {
	objSect, err := NewSectionObject(obj, partition, objType, objName, codeID, codeType, language, languageVersion, languageType, section, nil)
	if err != nil {
		return err
	}
	return m.AddSectionObject(objSect)
}

// AddSectionObjectWithError adds a section object with an error.
func (m *MultiSectionsObject) AddSectionObjectWithError(section int, err error) error {
	objSect, err := NewSectionObject(nil, "", "", "", "", "", "", "", "", section, err)
	if err != nil {
		return err
	}
	return m.AddSectionObject(objSect)
}
