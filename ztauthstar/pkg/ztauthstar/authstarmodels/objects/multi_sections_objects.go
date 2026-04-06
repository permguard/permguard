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
	obj       *Object
	partition string
	otype     string
	oname     string
	metadata  map[string]any
	numOfSect int
	err       error
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

// Metadata returns the metadata map.
func (s *SectionObject) Metadata() map[string]any {
	return s.metadata
}

// MetadataString returns a metadata value as a string.
func (s *SectionObject) MetadataString(key string) string {
	v, ok := s.metadata[key]
	if !ok {
		return ""
	}
	str, ok := v.(string)
	if !ok {
		return ""
	}
	return str
}

// MetadataUint32 returns a metadata value as a uint32.
func (s *SectionObject) MetadataUint32(key string) uint32 {
	v, ok := s.metadata[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case uint32:
		return n
	case uint64:
		return uint32(n)
	case int64:
		return uint32(n)
	case float64:
		return uint32(n)
	default:
		return 0
	}
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
func NewSectionObject(obj *Object, partition, objType, objName string, metadata map[string]any, section int, err error) (*SectionObject, error) {
	if metadata == nil {
		metadata = make(map[string]any)
	}
	return &SectionObject{
		partition: partition,
		obj:       obj,
		otype:     objType,
		oname:     objName,
		metadata:  metadata,
		numOfSect: section,
		err:       err,
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
func (m *MultiSectionsObject) AddSectionObjectWithParams(obj *Object, partition, objType, objName string, metadata map[string]any, section int) error {
	objSect, err := NewSectionObject(obj, partition, objType, objName, metadata, section, nil)
	if err != nil {
		return err
	}
	return m.AddSectionObject(objSect)
}

// AddSectionObjectWithError adds a section object with an error.
func (m *MultiSectionsObject) AddSectionObjectWithError(section int, err error) error {
	objSect, err := NewSectionObject(nil, "", "", "", nil, section, err)
	if err != nil {
		return err
	}
	return m.AddSectionObject(objSect)
}
