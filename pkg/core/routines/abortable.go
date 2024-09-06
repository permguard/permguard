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

package routines

// Abortable represents metadata about a routine that can be aborted.
type Abortable struct {
	aborted bool
	err     error
	message string
}

// NewAbortable creates a new abortable.
func NewAbortable() *Abortable {
	return &Abortable{
		aborted: false,
		err:     nil,
		message: "",
	}
}

// IsAborted returns true if the routine has been aborted.
func (a *Abortable) IsAborted() bool {
	return a.aborted
}

// GetError returns the error.
func (a *Abortable) GetError() error {
	return a.err
}

// GetMessage returns the message.
func (a *Abortable) GetMessage() string {
	return a.message
}

// Abort set as aborted.
func (a *Abortable) Abort(err error, message string) {
	a.aborted = true
	a.err = err
	a.message = message
}
