.DEFAULT_GOAL := build

# Windows executables always have .exe extension
WIN_EXE := .exe

# Binary names for Windows
DIST_DIR := dist
WIN_CLI := permguard$(WIN_EXE)
WIN_SERVER_ALL := server-all-in-one$(WIN_EXE)
WIN_SERVER_AAP := server-aap$(WIN_EXE)
WIN_SERVER_PAP := server-pap$(WIN_EXE)
WIN_SERVER_IDP := server-idp$(WIN_EXE)
WIN_SERVER_PDP := server-pdp$(WIN_EXE)

brew:
	brew install golangci-lint
	brew install staticcheck
	brew install gofumpt
	brew install protobuf

install:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/google/addlicense@latest

clean:
	rm -rf $(DIST_DIR)
	rm -rf tmp/
	rm -f coverage.out
	rm -f result.json

init-dependency:
	go get -u golang.org/x/crypto
	go get -u golang.org/x/net
	go get -u github.com/davecgh/go-spew
	go get -u github.com/xeipuuv/gojsonschema
	go get -u go.uber.org/zap
	go get -u github.com/go-playground/validator/v10
	go get -u google.golang.org/grpc
	go get -u github.com/spf13/cobra
	go get -u github.com/spf13/viper
	go get -u github.com/stretchr/testify
	go get -u github.com/fatih/color
	go get -u gopkg.in/yaml.v2
	go get -u github.com/DATA-DOG/go-sqlmock
	go get -u github.com/pressly/goose/v3
	go get -u gorm.io/gorm
	go get -u gorm.io/driver/sqlite
	go get -u github.com/mattn/go-sqlite3
	go get -u moul.io/zapgorm2
	go get -u github.com/pelletier/go-toml
	go get -u github.com/gofrs/flock
	go get -u github.com/permguard/permguard-core
	go get -u github.com/permguard/permguard-abs-language
	go get -u github.com/cedar-policy/cedar-go

mod:
	go mod download
	go mod tidy

protoc:
	protoc internal/agents/services/zap/endpoints/api/v1/*.proto --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative --proto_path=.
	protoc internal/agents/services/pap/endpoints/api/v1/*.proto --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative --proto_path=.
	protoc internal/agents/services/pdp/endpoints/api/v1/*.proto --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative --proto_path=.

check:
	staticcheck ./...

lint:
	go vet ./...
	gofmt -s -w **/**.go
	gofumpt -l -w .
	golangci-lint run --disable-all --enable staticcheck

lint-fix:
	gofmt -s -w **/**.go
	go vet ./...
	gofumpt -l -w .
	golangci-lint run ./... --fix

test:
	go test ./...

teste2e:
	E2E=TRUE GOFLAGS="-count=1" go test ./e2e/...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out
	rm coverage.out

coverage-plugin:
	go test -coverprofile=coverage.out ./plugin/...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out
	rm coverage.out

coverage-%:
	go test -coverprofile=coverage.out ./...

coverage-json:
	go test -json -coverprofile=coverage.out ./... > result.json

# Build Windows executables
build-windows:
	mkdir -p $(DIST_DIR)
	GOOS=windows GOARCH=amd64 go build -o $(DIST_DIR)/$(WIN_CLI) ./cmd/cli

build-all-in-one:
	mkdir -p dist
	go build -o dist/server-all-in-one ./cmd/server-all-in-one
	chmod +x dist/server-all-in-one
	go run ./cmd/provisioner-db-sqlite/main.go --up --dbdir ./dist --debug

build-release:
	mkdir -p dist
	go build -o dist/server-all-in-one ./cmd/server-all-in-one
	chmod +x dist/server-all-in-one
	go build -o dist/server-zap ./cmd/server-zap
	chmod +x dist/server-zap
	go build -o dist/server-pap ./cmd/server-pap
	chmod +x dist/server-pap
	go build -o dist/server-pip ./cmd/server-pip
	chmod +x dist/server-pip
	go build -o dist/server-pdp ./cmd/server-pdp
	chmod +x dist/server-pdp
	go build -o dist/permguard ./cmd/cli
	chmod +x dist/permguard
# Build for current platform
build-native:
	mkdir -p $(DIST_DIR)
	go build -o $(DIST_DIR)/server-all-in-one ./cmd/server-all-in-one
	chmod +x $(DIST_DIR)/server-all-in-one
	go build -o $(DIST_DIR)/server-aap ./cmd/server-aap
	chmod +x $(DIST_DIR)/server-aap
	go build -o $(DIST_DIR)/server-pap ./cmd/server-pap
	chmod +x $(DIST_DIR)/server-pap
	go build -o $(DIST_DIR)/server-idp ./cmd/server-idp
	chmod +x $(DIST_DIR)/server-idp
	go build -o $(DIST_DIR)/server-pdp ./cmd/server-pdp
	chmod +x $(DIST_DIR)/server-pdp
	go build -o $(DIST_DIR)/permguard ./cmd/cli
	chmod +x $(DIST_DIR)/permguard

run-release:
	go run ./cmd/server-all-in-one

# Build Windows executables
build-all: build-windows

build: clean mod build-windows

run: clean mod lint-fix run-release

# disallow any parallelism (-j) for Make
.NOTPARALLEL:

.PHONY: clean mod lint lint-fix build build-windows build-all run
