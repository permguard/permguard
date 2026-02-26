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

package decisions

import (
	"slices"
	"strings"
)

const (
	// DecisionLogNone represents no decision logging.
	DecisionLogNone DecisionLogKind = "NONE"
	// DecisionLogStdOut represents stdout decision logging.
	DecisionLogStdOut DecisionLogKind = "STDOUT"
	// DecisionLogFile represents file decision logging.
	DecisionLogFile DecisionLogKind = "FILE"
)

// DecisionLogKind is the type of decision log.
type DecisionLogKind string

// NewDecisionLogKindFromString creates a new decision log kind from a string.
func NewDecisionLogKindFromString(decisionLog string) (DecisionLogKind, error) {
	if strings.TrimSpace(decisionLog) == "" {
		decisionLog = string(DecisionLogNone)
	}
	return DecisionLogKind(strings.ToUpper(decisionLog)), nil
}

// String returns the string representation of the decision log kind.
func (s DecisionLogKind) String() string {
	return strings.ToUpper(string(s))
}

// Equal returns true if the decision log kind is equal to the input decision log kind.
func (s DecisionLogKind) Equal(decisionLog DecisionLogKind) bool {
	return s.String() == decisionLog.String()
}

// IsValid returns true if the decision log kind is valid.
func (s DecisionLogKind) IsValid(decisionLog []DecisionLogKind) bool {
	return slices.ContainsFunc(decisionLog, s.Equal)
}

// ShouldLogDecision checks if the decision log kind is valid for logging decisions.
func ShouldLogDecision(decisionLog string) bool {
	return DecisionLogKind(decisionLog).IsValid([]DecisionLogKind{DecisionLogStdOut, DecisionLogFile})
}
