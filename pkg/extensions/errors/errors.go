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

package errors

import (
	"errors"
	"fmt"
	"strings"
)

// SystemError custom error
type SystemError struct {
	error
	errCode    string
	errMessage string
}

// Code returns the error code.
func (e SystemError) Code() string {
	return e.errCode
}

// Message returns the error message.
func (e SystemError) Message() string {
	return e.errMessage
}

// Equal checks if the error is equal to the input error.
func (e SystemError) Equal(err error) bool {
	sysErr := ConvertToSystemError(err)
	if sysErr == nil {
		return false
	}
	return e.errCode == sysErr.errCode
}

// NewSystemError create a system error with the input error code.
func NewSystemError(errCode string) error {
	if !isErrorCodeDefined(errCode) {
		return NewSystemError("00000")
	}
	errMessage := errorCodes[errCode]
	return SystemError{
		error:      fmt.Errorf("code: %s, message: %s", errCode, errMessage),
		errCode:    errCode,
		errMessage: errMessage,
	}
}

// NewSystemErrorWithMessage create a system error with the input error code and message.
func NewSystemErrorWithMessage(errCode string, errMessage string) error {
	if isErrorCodeDefined(errCode) {
		return NewSystemError(errCode)
	} else if errMessage == "" {
		return NewSystemError("00000")
	}
	return SystemError{
		error:      fmt.Errorf("code: %s, message: %s", errCode, errMessage),
		errCode:    errCode,
		errMessage: errMessage,
	}
}

// WrapSystemError wrap a system error.
func WrapSystemError(err error, errMessage string) error {
	sysErr := ConvertToSystemError(err)
	if sysErr == nil || len(sysErr.errCode) != 5 {
		return NewSystemErrorWithMessage("", errMessage)
	}
	return SystemError{
		error:      fmt.Errorf("code: %s, message: %s", sysErr.errCode, errMessage),
		errCode:    sysErr.errCode,
		errMessage: errMessage,
	}
}

// IsSystemError checks if the error is a SystemError.
func IsSystemError(err error) bool {
	var sysErr = &SystemError{}
	return errors.As(err, sysErr)
}

// ConvertToSystemError converts the error to a SystemError.
func ConvertToSystemError(err error) *SystemError {
	var sysErr = &SystemError{}
	if errors.As(err, sysErr) {
		return sysErr
	}
	return nil
}

// IsErrorInClass verify if the error is in the class of the input mask.
func IsErrorInClass(err error, mask string) bool {
	sysErr := ConvertToSystemError(err)
	if sysErr == nil || len(sysErr.errCode) != 5 {
		return false
	}
	mask = strings.ToLower(mask)
	maskLen := len(mask)
	errorCodeStr := sysErr.errCode
	for i := 0; i < maskLen; i++ {
		if mask[i] != 'x' && mask[i] != errorCodeStr[i] {
			return false
		}
	}
	return true
}

// GetSuperclassErrorCode returns the superclass error code of the input error code.
func GetSuperclassErrorCode(code string) (error) {
	superclassCode := code[:2]
	for i := 2; i < len(code); i++ {
		superclassCode += "0"
	}
	errorCode := errorCodes[superclassCode]
	if errorCode == "" {
		return ErrUnknown
	}
	return NewSystemError(superclassCode)
}

// IsErrorWithCode verify if the error is a valid systemerror with the input code
func IsErrorWithCode(err error, errCode string) bool {
	sysErr := ConvertToSystemError(err)
	if sysErr == nil {
		return false
	}
	return sysErr.errCode == errCode
}

// AreErrorsEqual checks if the input errors are equal.
func AreErrorsEqual(err1, err2 error) bool {
	sysErr1 := ConvertToSystemError(err1)
	sysErr2 := ConvertToSystemError(err2)
	if sysErr1 == nil || sysErr2 == nil {
		return false
	}
	return sysErr1.errCode == sysErr2.errCode
}
