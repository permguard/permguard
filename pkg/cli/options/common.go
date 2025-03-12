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

package options

import (
	"flag"
	"slices"
	"strings"

	"github.com/spf13/viper"
	"go.uber.org/zap"

	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

const (
	flagDebug    = "debug"
	flagLogLevel = "log-level"

	// DebugLevel logs are typically voluminous, and are usually disabled in production.
	flagValLogLevelDebug = "DEBUG"
	// InfoLevel is the default logging priority.
	flagValLogLevelInfo = "INFO"
	// WarnLevel logs are more important than Info, but don't need individual human review.
	flagValLogLevelWarn = "WARN"
	// ErrorLevel logs are high-priority. If a zone is running smoothly, it shouldn't generate any error-level logs.
	flagValLogLevelError = "ERROR"
	// DPanicLevel logs are particularly important errors. In development the logger panics after writing the message.
	flagValLogLevelDPanic = "DPANIC"
	// PanicLevel logs a message, then panics.
	flagValLogLevelPanic = "PANIC"
	// FatalLevel logs a message, then calls os.Exit(1).
	flagValLogLevelFatal = "FATAL"
)

// configValueLogLevels is the list of valid log levels.
var configValueLogLevels = []string{flagValLogLevelDebug, flagValLogLevelInfo, flagValLogLevelWarn, flagValLogLevelError, flagValLogLevelDPanic, flagValLogLevelPanic, flagValLogLevelFatal}

// AddFlagsForCommon adds the common flags to the flag set.
func AddFlagsForCommon(flagSet *flag.FlagSet) error {
	flagSet.Bool(flagDebug, false, "enable debug mode")
	flagSet.String(FlagName(flagLogLevel), flagValLogLevelInfo, "specifies log level")
	return nil
}

// InitFromViperForCommon initializes the common configuration from the viper.
func InitFromViperForCommon(v *viper.Viper) (bool, string, error) {
	debug := v.GetBool(flagDebug)
	logLevel := strings.ToUpper(v.GetString(FlagName(flagLogLevel)))
	if !slices.Contains(configValueLogLevels, strings.ToUpper(logLevel)) {
		return false, "", azerrors.WrapSystemErrorWithMessage(azerrors.ErrCliGeneric, "invalid log level")
	}
	return debug, logLevel, nil
}

// NewLogger creates a new logger.
func NewLogger(debug bool, logLevel string) (*zap.Logger, error) {
	var config zap.Config
	if debug {
		config = zap.NewDevelopmentConfig()
	} else {
		config = zap.NewProductionConfig()
	}
	switch logLevel {
	case flagValLogLevelDebug:
		config.Level.SetLevel(zap.DebugLevel)
	case flagValLogLevelInfo:
		config.Level.SetLevel(zap.InfoLevel)
	case flagValLogLevelWarn:
		config.Level.SetLevel(zap.WarnLevel)
	case flagValLogLevelError:
		config.Level.SetLevel(zap.ErrorLevel)
	case flagValLogLevelDPanic:
		config.Level.SetLevel(zap.DPanicLevel)
	case flagValLogLevelPanic:
		config.Level.SetLevel(zap.PanicLevel)
	case flagValLogLevelFatal:
		config.Level.SetLevel(zap.FatalLevel)
	}
	logger, err := config.Build()
	if err != nil {
		return nil, err
	}
	return logger, nil
}
