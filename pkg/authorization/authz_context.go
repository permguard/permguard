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

package authorization

// AuthorizationContext represents the authorization context.
type AuthorizationContext struct {
	subject  *Subject
	resource *Resource
	action   *Action
	context  map[string]any
	entities *Entities
}

// SetSubject sets the subject of the authorization context.
func (a *AuthorizationContext) SetSubject(kind string, id string, source string, properties map[string]any) error {
	a.subject = &Subject{
		kind:       kind,
		id:         id,
		source:     source,
		properties: properties,
	}
	return nil
}

// GetSubject returns the subject of the authorization context.
func (a *AuthorizationContext) GetSubject() *Subject {
	return a.subject
}

// SetResource sets the resource of the authorization context.
func (a *AuthorizationContext) SetResource(kind string, id string, properties map[string]any) error {
	a.resource = &Resource{
		kind:       kind,
		id:         id,
		properties: properties,
	}
	return nil
}

// GetResource returns the resource of the authorization context.
func (a *AuthorizationContext) GetResource() *Resource {
	return a.resource
}

// SetAction sets the action of the authorization context.
func (a *AuthorizationContext) SetAction(id string, properties map[string]any) error {
	a.action = &Action{
		id:         id,
		properties: properties,
	}
	return nil
}

// GetAction returns the action of the authorization context.
func (a *AuthorizationContext) GetAction() *Action {
	return a.action
}

// SetEntities sets the entities of the authorization context.
func (a *AuthorizationContext) SetEntities(schema string, items []map[string]any) error {
	a.entities = &Entities{
		schema: schema,
		items:  items,
	}
	return nil
}

// GetEntities returns the entities of the authorization context.
func (a *AuthorizationContext) GetEntities() *Entities {
	return a.entities
}

// SetContext sets the context of the authorization context.
func (a *AuthorizationContext) SetContext(context map[string]any) error {
	a.context = context
	return nil
}

// GetContext returns the context of the authorization context.
func (a *AuthorizationContext) GetContext() map[string]any {
	return a.context
}
