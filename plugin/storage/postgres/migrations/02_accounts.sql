-- Copyright 2024 Nitro Agility S.r.l.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
CREATE TABLE accounts (
    account_id BIGINT PRIMARY KEY NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    status SMALLINT NOT NULL DEFAULT 1,
    name VARCHAR(254) NOT NULL UNIQUE,
	-- CONSTRAINTS
	CONSTRAINT accounts_accountid_name_key UNIQUE (name)
);

CREATE INDEX accounts_name_idx ON accounts(name);

-- +goose StatementBegin
CREATE FUNCTION udf_gen_random_id()
RETURNS TRIGGER AS $$
BEGIN
    NEW.account_id := (100000000000 + (TRUNC(random() * 900000000000))::BIGINT);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER bfr_i_accounts
BEFORE INSERT ON accounts
FOR EACH ROW
EXECUTE FUNCTION udf_gen_random_id();

CREATE TRIGGER bfr_u_accounts
	BEFORE UPDATE ON accounts
	FOR EACH ROW EXECUTE FUNCTION udf_row_update_timestamp();

-- +goose Down
DROP TRIGGER IF EXISTS bfr_u_accounts ON accounts;
DROP TABLE IF EXISTS accounts CASCADE;
DROP FUNCTION IF EXISTS udf_gen_random_id CASCADE;
