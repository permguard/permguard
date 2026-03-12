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

package services

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/permguard/permguard/pkg/agents/services"
	"github.com/permguard/permguard/pkg/agents/storage"
)

// JobConfig represents the job configuration.
type JobConfig struct {
	hostable         services.Hostable
	storageConnector *storage.Connector
	service          services.ServiceKind
	name             string
	run              func(context.Context, *services.ServiceContext, *storage.Connector) error
}

// newJobConfig creates a new job configuration.
func newJobConfig(hostable services.Hostable, service services.ServiceKind, storageConnector *storage.Connector, name string, run func(context.Context, *services.ServiceContext, *storage.Connector) error) *JobConfig {
	return &JobConfig{
		hostable:         hostable,
		storageConnector: storageConnector,
		service:          service,
		name:             name,
		run:              run,
	}
}

// Job represents a background job.
type Job struct {
	config *JobConfig
	cancel context.CancelFunc
	done   chan struct{}
	logger *zap.Logger
}

// newJob creates a new job.
func newJob(jobCfg *JobConfig, logger *zap.Logger) *Job {
	return &Job{
		config: jobCfg,
		logger: logger,
		done:   make(chan struct{}),
	}
}

// Serve starts the job in a background goroutine.
func (j *Job) Serve(ctx context.Context, serviceCtx *services.ServiceContext) (bool, error) {
	jobCtx, cancel := context.WithCancel(ctx)
	j.cancel = cancel
	j.logger.Debug("Job is starting", zap.String("job_name", j.config.name))
	go func() {
		defer func() {
			close(j.done)
			if r := recover(); r != nil {
				j.logger.Error("Job generated a panic",
					zap.String("job_name", j.config.name),
					zap.Any("panic", r))
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer shutdownCancel()
				j.config.hostable.Shutdown(shutdownCtx)
			}
		}()
		if err := j.config.run(jobCtx, serviceCtx, j.config.storageConnector); err != nil {
			j.logger.Error("Job failed",
				zap.String("job_name", j.config.name),
				zap.Error(err))
		}
	}()
	j.logger.Debug("Job has started", zap.String("job_name", j.config.name))
	return true, nil
}

// GracefulStop stops the job.
func (j *Job) GracefulStop(_ context.Context) (bool, error) {
	j.logger.Debug("Job is stopping", zap.String("job_name", j.config.name))
	if j.cancel != nil {
		j.cancel()
	}
	<-j.done
	j.logger.Debug("Job has stopped", zap.String("job_name", j.config.name))
	return true, nil
}
