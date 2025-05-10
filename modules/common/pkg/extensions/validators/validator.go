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

package validators

import (
	"os"
	"regexp"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

// isSimpleName is a custom validator for simple name.
func isSimpleName(fl validator.FieldLevel) bool {
	pattern := `^[a-z][a-z0-9]*[a-z0-9]$`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(fl.Field().String())
}

// isName is a custom validator for name.
func isName(fl validator.FieldLevel) bool {
	pattern := `^[a-z0-9][a-z0-9\-\._]*[a-z0-9]$`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(fl.Field().String())
}

// isWildcardName is a custom validator for wilcard name.
func isWildcardName(fl validator.FieldLevel) bool {
	pattern := `^[a-z\*][a-z0-9\*\-\._]*[a-z0-9\*]*$`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(fl.Field().String())
}

// isUUID is a custom validator for UUID.
func isUUID(fl validator.FieldLevel) bool {
	_, err := uuid.Parse(fl.Field().String())
	return err == nil
}

// dirpath is a custom validator for directory path.
func dirpath(fl validator.FieldLevel) bool {
	path := fl.Field().String()
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir() // ensure the path is a directory
}

// ValidateInstance validates the input instance.
func ValidateInstance(s any) (bool, error) {
	if s == nil {
		return false, nil
	}
	validate := validator.New()
	validate.RegisterValidation("isuuid", isUUID)
	validate.RegisterValidation("simplename", isSimpleName)
	validate.RegisterValidation("name", isName)
	validate.RegisterValidation("wildcardname", isWildcardName)
	validate.RegisterValidation("dirpath", dirpath)
	err := validate.Struct(s)
	if err != nil {
		return false, err
	}
	return true, nil
}
