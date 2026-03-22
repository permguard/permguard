// Copyright 2024 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

package objects

import (
	"database/sql/driver"
	"encoding/json"
	"strings"
)

// CID is a wrapper for a valid content identifier string (CIDv1, base32).
type CID string

// IsValid checks if the CID is valid (basic check, can be extended).
func (c CID) IsValid() bool {
	return strings.HasPrefix(string(c), "bafy") && len(c) > 10
}

func (c CID) String() string {
	return string(c)
}

// MarshalJSON ensures CID is marshaled as a string.
func (c CID) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(c))
}

// UnmarshalJSON ensures CID is unmarshaled from a string.
func (c *CID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*c = CID(s)
	return nil
}

// NullableString is a wrapper for a string that can be null.
type NullableString struct {
	String string
	Valid  bool
}

func NewNullableString(s *string) NullableString {
	if s == nil {
		return NullableString{"", false}
	}
	return NullableString{*s, true}
}

func (ns NullableString) Ptr() *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

// Scan implements the sql.Scanner interface.
func (ns *NullableString) Scan(value interface{}) error {
	s, ok := value.(string)
	if !ok {
		ns.String, ns.Valid = "", false
		return nil
	}
	ns.String, ns.Valid = s, true
	return nil
}

// Value implements the driver.Valuer interface.
func (ns NullableString) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return ns.String, nil
}

// MarshalJSON for NullableString.
func (ns NullableString) MarshalJSON() ([]byte, error) {
	if !ns.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(ns.String)
}

// UnmarshalJSON for NullableString.
func (ns *NullableString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		ns.String, ns.Valid = "", false
		return nil
	}
	if err := json.Unmarshal(data, &ns.String); err != nil {
		ns.Valid = false
		return err
	}
	ns.Valid = true
	return nil
}
