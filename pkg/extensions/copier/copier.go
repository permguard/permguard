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

package copier

import (
	"maps"

	jinzhuCopier "github.com/jinzhu/copier"
)

// CopySlice returns a new slice with shallow copies of the elements from the input slice.
// If the input slice is nil, returns nil.
// This function performs a shallow copy, meaning nested pointers or slices will share references.
func CopySlice[T any](slice []T) []T {
	if slice == nil {
		return nil
	}
	newSlice := make([]T, len(slice))
	copy(newSlice, slice)
	return newSlice
}

// CopyMap returns a new map with shallow copies of the key-value pairs from the input map.
// If the input map is nil, returns nil.
// This function performs a shallow copy, meaning nested values that are pointers or slices will share references.
func CopyMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return nil
	}
	c := make(map[K]V, len(m))
	maps.Copy(c, m)
	return c
}

// Copy copies the fields from fromValue to toValue using reflection.
// It performs a shallow copy by default. Returns an error if the copy operation fails,
// such as when types are incompatible or if reflection encounters issues.
// For deep copying, consider using the underlying library's options or alternative methods.
func Copy(toValue any, fromValue any) error {
	return jinzhuCopier.Copy(toValue, fromValue)
}
