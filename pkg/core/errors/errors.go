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

const (
	// errorMessageCodeMsg is the error message code message.
	errorMessageCodeMsg = "error code: %s, message: %s"
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
	if !isValidErrorCodeFormat(errCode) {
		errCode = "00000"
	}
	defErrCode := errCode
	if !isErrorCodeDefined(errCode) {
		defErrCode = getSuperClassFromCode(errCode)
		if defErrCode == "00000" && errCode[:2] != "00" {
			errCode = defErrCode
		}
	}
	errMessage := strings.ToLower(errorCodes[defErrCode])
	return SystemError{
		error:      fmt.Errorf(errorMessageCodeMsg, errCode, errMessage),
		errCode:    errCode,
		errMessage: errMessage,
	}
}

// NewSystemErrorWithMessage create a system error with the input error code and message.
func NewSystemErrorWithMessage(errCode string, errMessage string) error {
	if !isValidErrorCodeFormat(errCode) {
		errCode = "00000"
	}
	sysErr := NewSystemError(errCode).(SystemError)
	cleanMessage := strings.TrimSpace(strings.TrimSuffix(errMessage, "."))
	if len(cleanMessage) == 0 {
		return sysErr
	}
	cleanMessage = strings.ToLower(transformErroMessageString(sysErr.errMessage, cleanMessage))
	if len(cleanMessage) > 0 {
		sysErr.error = fmt.Errorf(errorMessageCodeMsg, sysErr.errCode, cleanMessage)
		sysErr.errMessage = cleanMessage
	}
	return sysErr
}

// ConvertToSystemError converts the error to a SystemError.
func ConvertToSystemError(err error) *SystemError {
	var sysErr = &SystemError{}
	if errors.As(err, sysErr) {
		if !isErrorCodeDefined(sysErr.errCode) {
			if !isErrorCodeDefined(getSuperClassFromCode(sysErr.errCode)) {
				return nil
			}
		}
		return sysErr
	}
	return nil
}

// IsErrorInClass verify if the error is in the class of the input mask.
func IsErrorInClass(err error, mask string) bool {
	sysErr := ConvertToSystemError(err)
	if sysErr == nil {
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

// AreErrorsEqual checks if the input errors are equal.
func AreErrorsEqual(err1, err2 error) bool {
	sysErr1 := ConvertToSystemError(err1)
	sysErr2 := ConvertToSystemError(err2)
	if sysErr1 == nil || sysErr2 == nil {
		return false
	}
	return sysErr1.errCode == sysErr2.errCode
}

// WrapSystemError wrap a system error.
func WrapSystemError(err error) error {
	sysErr := ConvertToSystemError(err)
	if sysErr == nil {
		return NewSystemError("")
	}
	return NewSystemError(sysErr.errCode)
}

// WrapSystemErrorWithMessage wrap a system error with a message.
func WrapSystemErrorWithMessage(err error, errMessage string) error {
	errMessage = strings.TrimSuffix(errMessage, ".")
	sysErr := ConvertToSystemError(err)
	if sysErr == nil {
		return NewSystemErrorWithMessage("", errMessage)
	}
	return NewSystemErrorWithMessage(sysErr.errCode, errMessage)
}

// WrapHandledSysError wrap an handled error and a system error.
func WrapHandledSysError(err error, handledErr error) error {
	sysErr := WrapSystemError(err).(SystemError)
	if handledErr == nil {
		sysErr.errMessage = fmt.Sprintf("%s. %s", sysErr.errMessage, err.Error())
	}
	return sysErr
}

// WrapHandledSysErrorWithMessage wrap an handled error and a system error with a message.
func WrapHandledSysErrorWithMessage(err error, errMessage string, handledErr error) error {
	sysErr := WrapSystemErrorWithMessage(err, errMessage).(SystemError)
	if handledErr == nil {
		sysErr.errMessage = fmt.Sprintf("%s. %s", sysErr.errMessage, err.Error())
	}
	return sysErr
}
