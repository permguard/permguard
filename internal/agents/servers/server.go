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

package servers

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"go.uber.org/zap"

	aziservices "github.com/permguard/permguard/internal/agents/services"
	azservices "github.com/permguard/permguard/pkg/agents/services"
	azstorage "github.com/permguard/permguard/pkg/agents/storage"
	azoptions "github.com/permguard/permguard/pkg/cli/options"
)

// Server represents the applicative server.
type Server struct {
	config      *ServerConfig
	started     bool
	startLock   sync.Mutex
	stopChannel chan os.Signal
	logger      *zap.Logger
}

// newServer creates a new server.
func newServer(serverCfg *ServerConfig) (*Server, error) {
	logger, err := azoptions.NewLogger(serverCfg.debug, serverCfg.logLevel)
	if err != nil {
		return nil, err
	}
	srv := &Server{
		config: serverCfg,
		logger: logger,
	}
	return srv, nil
}

// GetHost returns the hsot kind.
func (s *Server) GetHost() azservices.HostKind {
	return s.config.host
}

// HasDebug returns true if debug is enabled.
func (s *Server) HasDebug() bool {
	return s.config.debug
}

// GetLogger returns the logger.
func (s *Server) GetLogger() *zap.Logger {
	return s.logger
}

// serveExecStop executes the server stop.
func serveExecStop(ctx context.Context, logger *zap.Logger, hasStarted bool, host *aziservices.Host, onShutdown func(), s *Server) {
	logger.Info("Bootstrapper is stopping the server")
	if hasStarted {
		done, err := host.GracefulStop(ctx)
		if err != nil {
			logger.Error("Bootstrapper could not execute the GracefulStop successfully", zap.Error(err))
		}
		if !done {
			logger.Error("Bootstrapper could not execute the GracefulStop successfully", zap.Error(err))
		}
	}
	if onShutdown != nil {
		logger.Info("Bootstrapper is calling onshutdown")
		onShutdown()
		logger.Info("Bootstrapper has called onshutdown")
	}
	s.started = false
	logger.Info("Bootstrapper has stopped the server")
}

// Serve runs the server and then calls the onshutdown function.
func (s *Server) Serve(ctx context.Context, onShutdown func()) (bool, error) {
	logger := s.logger
	logger.Info("Bootstrapper is starting the server")
	s.startLock.Lock()
	if s.started {
		s.startLock.Unlock()
		logger.Info("Bootstrapper cannot start the server has it is already started")
		return false, nil
	}

	storageConnector, err := azstorage.NewStorageConnector(s.config.GetStoragesFactories())
	if err != nil {
		logger.Error("Bootstrapper cannot create the storage connector", zap.Error(err))
		s.startLock.Unlock()
		return false, err
	}
	hostCfg, err := aziservices.NewHostConfig(s.config.GetHost(), s, storageConnector, s.config.GetServices(), s.config.GetServicesFactories(), logger, s.config.GetAppData())
	if err != nil {
		logger.Error("Bootstrapper cannot create the host config", zap.Error(err))
		s.startLock.Unlock()
		return false, err
	}
	host, err := aziservices.NewHost(hostCfg)
	if err != nil {
		logger.Error("Bootstrapper cannot create the host", zap.Error(err))
		s.startLock.Unlock()
		return false, err
	}

	stopChannel := make(chan os.Signal, 1)
	signal.Notify(stopChannel, os.Interrupt, syscall.SIGTERM)
	s.stopChannel = stopChannel
	defer signal.Stop(s.stopChannel)

	hasStarted, err := host.Serve(ctx)
	if err != nil {
		logger.Error("Bootstrapper cannot serve the host", zap.Error(err))
		s.startLock.Unlock()
		return false, err
	}

	stop := func() {
		serveExecStop(ctx, logger, hasStarted, host, onShutdown, s)
	}

	if hasStarted {
		s.started = true
		s.startLock.Unlock()

		select {
		case <-ctx.Done():
			stop()
		case <-s.stopChannel:
			stop()
		}
	} else {
		stop()
		s.startLock.Unlock()
	}
	fmt.Print(host)
	return hasStarted, nil
}

// Shutdown signals the server to shutdown.
func (s *Server) Shutdown(ctx context.Context) {
	s.startLock.Lock()
	defer s.startLock.Unlock()

	if !s.started {
		return
	}
	select {
	case <-ctx.Done():
		s.stopChannel <- syscall.SIGTERM
		return
	case s.stopChannel <- syscall.SIGTERM:
		return
	}
}
