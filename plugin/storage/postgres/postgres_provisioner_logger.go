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

package postgres

import (
	"fmt"

	"go.uber.org/zap"
)

// GooseLogger is a logger for goose.
type GooseLogger struct {
	logger *zap.Logger
}

// Printf logs a message.
func (l *GooseLogger) Printf(format string, v ...any) {
	l.logger.Info(fmt.Sprintf(format, v...))
}

// Fatalf logs a fatal error.
func (l *GooseLogger) Fatalf(format string, v ...any) {
	l.logger.Fatal(fmt.Sprintf(format, v...))
}
