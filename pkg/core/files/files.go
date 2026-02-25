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

package files

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/pelletier/go-toml"
)

// Path

// CheckPathIfExists checks if a path exists.
func CheckPathIfExists(name string) (bool, error) {
	if _, err := os.Stat(name); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	}
	return true, nil
}

// DeletePath deletes the input directory.
func DeletePath(name string) (bool, error) {
	var err error
	if _, err = os.Stat(name); err == nil {
		err = os.RemoveAll(name)
		if err != nil {
			return false, errors.New("core: failed to remove directory")
		}
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, errors.New("core: failed to stat directory")
	}
	return true, nil
}

// Directories

// CreateDirIfNotExists creates a directory if it does not exist.
func CreateDirIfNotExists(name string) (bool, error) {
	if _, err := os.Stat(name); err == nil {
		return false, nil
	} else if os.IsNotExist(err) {
		err := os.MkdirAll(name, 0o755)
		if err != nil {
			return false, errors.New("core: failed to create directory")
		}
	} else {
		return false, errors.New("core: failed to stat directory")
	}
	return true, nil
}

// Files

// GenerateUniqueFile generates a unique file name.
func GenerateUniqueFile(prefix string, extension string) (string, error) {
	timestamp := time.Now().Unix() % 1000000
	randomBytes := make([]byte, 4)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("core: failed to generate an unique file name %v", err)
	}
	randomString := hex.EncodeToString(randomBytes)
	fileName := fmt.Sprintf("%s-%d-%s.%s", prefix, timestamp, randomString, extension)
	return fileName, nil
}

// CreateFileIfNotExists creates a file if it does not exist.
func CreateFileIfNotExists(name string) (bool, error) {
	_, err := os.Stat(name)
	switch {
	case err == nil:
		return false, nil
	case os.IsNotExist(err):
		err = os.MkdirAll(filepath.Dir(name), 0o755)
		if err != nil {
			return false, errors.New("core: failed to create directory")
		}
		file, err := os.Create(name)
		if err != nil {
			return false, errors.New("core: failed to create file")
		}
		defer file.Close()
	case os.IsExist(err):
		return false, nil
	default:
		return false, errors.New("core: failed to stat file")
	}
	return true, nil
}

// WriteFileIfNotExists writes a file if it does not exist.
func WriteFileIfNotExists(name string, data []byte, perm os.FileMode, compressed bool) (bool, error) {
	_, err := os.Stat(name)
	switch {
	case err == nil:
		return false, nil
	case os.IsExist(err):
		return false, nil
	case os.IsNotExist(err):
		return WriteFile(name, data, perm, compressed)
	default:
		return false, errors.New("core: failed to stat file")
	}
}

// WriteFile writes a file.
func WriteFile(name string, data []byte, perm os.FileMode, compressed bool) (bool, error) {
	if compressed {
		var buf bytes.Buffer
		zlibWriter := zlib.NewWriter(&buf)
		_, err := zlibWriter.Write(data)
		if err != nil {
			return false, errors.New("core: failed to compress data")
		}
		err = zlibWriter.Close()
		if err != nil {
			return false, errors.New("core: failed to close zlib writer")
		}
		err = os.WriteFile(name, buf.Bytes(), perm)
		if err != nil {
			return false, errors.New("core: failed to write compressed file")
		}
	} else {
		err := os.WriteFile(name, data, perm)
		if err != nil {
			return false, errors.New("core: failed to write file")
		}
	}
	return true, nil
}

// AppendToFile appends to a file.
func AppendToFile(name string, data []byte, compressed bool) (bool, error) {
	existingData, _, err := ReadFile(name, compressed)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, errors.New("core: failed to read file")
	}
	newData := append(existingData, data...)
	return WriteFile(name, newData, 0o644, compressed)
}

// ReadFile reads a file.
func ReadFile(name string, compressed bool) ([]byte, uint32, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, 0, err
	}
	info, err := os.Stat(name)
	if err != nil {
		return nil, 0, err
	}
	mode := uint32(info.Mode().Perm())
	if compressed {
		var buf bytes.Buffer
		buf.Write(data)
		zr, err := zlib.NewReader(&buf)
		if err != nil {
			return nil, 0, err
		}
		defer zr.Close()
		var decompressed bytes.Buffer
		_, err = io.Copy(&decompressed, zr)
		if err != nil {
			return nil, 0, err
		}
		data = decompressed.Bytes()
	}
	return data, mode, nil
}

// Search

// normalizePattern normalizes a pattern.
func normalizePattern(pattern string) string {
	if strings.Contains(pattern, "***") {
		pattern = strings.ReplaceAll(pattern, "***", "**")
	}
	if strings.HasPrefix(pattern, "**/") {
		pattern = strings.TrimPrefix(pattern, "**/")
		pattern = "**" + pattern
	}
	return pattern
}

// shouldIgnore checks if a file should be ignored.
func shouldIgnore(path string, root string, ignorePatterns []string) bool {
	ignored := false
	for _, pattern := range ignorePatterns {
		isNegation := strings.HasPrefix(pattern, "!")
		pattern = strings.TrimPrefix(pattern, "!")
		pattern = normalizePattern(pattern)
		fullPattern := filepath.Join(root, pattern)
		matches, _ := filepath.Glob(fullPattern)
		for _, match := range matches {
			if match == path {
				if isNegation {
					ignored = false
				} else {
					ignored = true
				}
			}
		}
	}
	return ignored
}

// ListDirectories lists directories.
func ListDirectories(path string) ([]string, error) {
	var directories []string
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			directories = append(directories, entry.Name())
		}
	}
	return directories, nil
}

// ListFiles lists files.
func ListFiles(path string) ([]string, error) {
	var files []string
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

// ScanAndFilterFiles scans and filters files.
func ScanAndFilterFiles(rootDir string, exts []string, ignorePatterns []string) ([]string, []string, error) {
	var files []string
	var ignoredFiles []string
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if shouldIgnore(path, rootDir, ignorePatterns) {
			ignoredFiles = append(ignoredFiles, path)
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.IsDir() {
			if len(exts) > 0 {
				matched := false
				for _, ext := range exts {
					if strings.HasSuffix(strings.ToLower(info.Name()), strings.ToLower(ext)) {
						matched = true
						break
					}
				}
				if !matched {
					ignoredFiles = append(ignoredFiles, path)
					return nil
				}
			}
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return files, ignoredFiles, nil
}

// CSV

// WriteCSVStream writes a CSV stream.
func WriteCSVStream(filename string, header []string, records any, rowFunc func(any) []string, compressed bool) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	var writer io.Writer = file
	if compressed {
		zlibWriter := zlib.NewWriter(file)
		defer zlibWriter.Close()
		writer = zlibWriter
	}
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()
	if header == nil {
		if err := csvWriter.Write(header); err != nil {
			return err
		}
	}
	v := reflect.ValueOf(records)
	if v.Kind() != reflect.Slice {
		return errors.New("core: records must be a slice")
	}
	for i := 0; i < v.Len(); i++ {
		record := v.Index(i).Interface()
		row := rowFunc(record)
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// ReadCSVStream reads from a CSV stream.
func ReadCSVStream(filename string, header []string, recordFunc func([]string) error, compressed bool) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	var reader io.Reader = file
	if compressed {
		zlibReader, err := zlib.NewReader(file)
		if err != nil {
			return err
		}
		defer zlibReader.Close()
		reader = zlibReader
	}
	csvReader := csv.NewReader(reader)
	if header != nil {
		if _, err := csvReader.Read(); err != nil {
			return err
		}
	}
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := recordFunc(record); err != nil {
			return err
		}
	}
	return nil
}

// Ignore file

// ReadIgnoreFile reads an ignore file.
func ReadIgnoreFile(name string) ([]string, error) {
	var ignorePatterns []string
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ignorePatterns = append(ignorePatterns, line)
	}
	return ignorePatterns, nil
}

// TOML

// ReadTOMLFile reads a TOML file.
func ReadTOMLFile(name string, v any) error {
	file, err := os.Open(name)
	if err != nil {
		return errors.New("core: failed to open file")
	}
	defer file.Close()
	b, err := io.ReadAll(file)
	if err != nil {
		return errors.New("core: failed to read file")
	}
	err = toml.Unmarshal(b, v)
	if err != nil {
		return errors.New("core: failed to unmarshal TOML")
	}
	return nil
}
