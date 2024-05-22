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
	"database/sql"
	"embed"
	"flag"
	"fmt"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	azconfigs "github.com/permguard/permguard/pkg/configs"
)

const (
	flagUp   = "up"
	flagDown = "down"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

// PostgresStorageProvisioner is the storage provisioner for Postgres.
type PostgresStorageProvisioner struct {
	debug    bool
	logLevel string
	logger   *zap.Logger
	up       bool
	down     bool
	config   *PostgresConnectionConfig
}

// NewPostgresStorageProvisioner creates a new PostgresStorageProvisioner.
func NewPostgresStorageProvisioner() (*PostgresStorageProvisioner, error) {
	config, err := newPostgresConnectionConfig()
	if err != nil {
		return nil, err
	}
	return &PostgresStorageProvisioner{
		config: config,
	}, nil
}

// AddFlags adds flags.
func (p *PostgresStorageProvisioner) AddFlags(flagSet *flag.FlagSet) error {
	err := azconfigs.AddFlagsForCommon(flagSet)
	if err != nil {
		return err
	}
	flagSet.Bool(flagUp, false, "provision the database")
	flagSet.Bool(flagDown, false, "deprovision the database")
	err = p.config.AddFlags(flagSet)
	if err != nil {
		return err
	}
	return nil
}

// InitFromViper initializes the configuration from viper.
func (p *PostgresStorageProvisioner) InitFromViper(v *viper.Viper) error {
	debug, logLevel, err := azconfigs.InitFromViperForCommon(v)
	if err != nil {
		return err
	}
	p.debug = debug
	p.logLevel = logLevel
	p.up = v.GetBool(flagUp)
	p.down = v.GetBool(flagDown)
	err = p.config.InitFromViper(v)
	if err != nil {
		return err
	}
	p.logger, err = azconfigs.NewLogger(p.debug, p.logLevel)
	if err != nil {
		return err
	}
	return nil
}

// setup sets up the database.
func (p *PostgresStorageProvisioner) setup() (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		p.config.GetHost(), p.config.GetPort(), p.config.GetUsername(), p.config.GetPassword(), p.config.GetDatabase())
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	goose.SetLogger(&GooseLogger{logger: p.logger})
	goose.SetBaseFS(embedMigrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return nil, err
	}
	return db, nil
}

// Up provisions the database.
func (p *PostgresStorageProvisioner) Up() error {
	if !p.up {
		p.logger.Info("Database provisioning skipped")
		return nil
	}
	p.logger.Debug("Provisioning database")
	db, err := p.setup()
	if err != nil {
		p.logger.Error("Database provisioning failed", zap.Error(err))
		return err
	}
	defer db.Close()
	if err := goose.Up(db, "migrations"); err != nil {
		p.logger.Error("Database provisioning failed", zap.Error(err))
		return err
	}
	p.logger.Info("Database provisioned")
	return nil
}

// Down deprovisions the database.
func (p *PostgresStorageProvisioner) Down() error {
	if !p.down {
		p.logger.Info("Database deprovisioning skipped")
		return nil
	}
	p.logger.Debug("Deprovisioning database")
	db, err := p.setup()
	if err != nil {
		p.logger.Error("Database deprovisioning failed", zap.Error(err))
		return err
	}
	defer db.Close()
	for err == nil {
		err = goose.Down(db, "migrations")
	}
	p.logger.Info("Database deprovisioned")
	return nil
}
