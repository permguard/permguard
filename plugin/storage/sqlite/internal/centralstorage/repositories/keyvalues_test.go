package repositories

import (
	"database/sql"
	"regexp"
	"testing"

	"github.com/mattn/go-sqlite3"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"

	"github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/repositories/testutils"
)

// registerKeyValueForUpsertMocking registers a key-value pair for upsert mocking.
func registerKeyValueForUpsertMocking() (*KeyValue, string, *sqlmock.Rows) {
	keyValue := &KeyValue{
		ZoneID: 45645646,
		Key:    "test-key",
		Value:  []byte("test-value"),
	}
	var sql = `INSERT INTO key_values \(zone_id, kv_key, kv_value\) VALUES \(\?, \?, \?\) ON CONFLICT\(zone_id, kv_key\) DO UPDATE SET kv_value = excluded.kv_value`
	sqlRows := sqlmock.NewRows([]string{"zone_id", "kv_key", "kv_value"}).
		AddRow(keyValue.ZoneID, keyValue.Key, keyValue.Value)
	return keyValue, sql, sqlRows
}

// TestRepoUpsertKeyValueWithInvalidInput tests the upsert of a key-value pair with invalid input.
func TestRepoUpsertKeyValueWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, _ := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with nil key-value
		_, err := ledger.UpsertKeyValue(tx, nil)
		assert.NotNil(err, "error should be not nil")
		assert.NotNil(err, "error should not be nil")
	}

	{ // Test with empty key
		keyValue := &KeyValue{
			Key:   "",
			Value: []byte("test-value"),
		}
		_, err := ledger.UpsertKeyValue(tx, keyValue)
		assert.NotNil(err, "error should be not nil")
		assert.NotNil(err, "error should not be nil")
	}
}

// TestRepoUpsertKeyValueWithSuccess tests the upsert of a key-value pair with success.
func TestRepoUpsertKeyValueWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}
	_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	keyValue, sql, sqlKeyValueRows := registerKeyValueForUpsertMocking()

	sqlDBMock.ExpectBegin()
	sqlDBMock.ExpectExec(sql).
		WithArgs(keyValue.ZoneID, keyValue.Key, keyValue.Value).
		WillReturnResult(sqlmock.NewResult(1, 1))

	sqlDBMock.ExpectQuery(`SELECT zone_id, kv_key, kv_value FROM key_values WHERE zone_id = \? and kv_key = \?`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlKeyValueRows)

	tx, _ := sqlDB.Begin()
	dbOutKeyValue, err := ledger.UpsertKeyValue(tx, keyValue)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutKeyValue, "key-value should be not nil")
	assert.Equal(keyValue.Key, dbOutKeyValue.Key, "key is not correct")
	assert.Equal(keyValue.Value, dbOutKeyValue.Value, "value is not correct")
	assert.Nil(err, "error should be nil")
}

// TestRepoUpsertKeyValueWithErrors tests the upsert of a key-value pair with errors.
func TestRepoUpsertKeyValueWithErrors(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	keyValue, sql, _ := registerKeyValueForUpsertMocking()

	sqlDBMock.ExpectBegin()
	sqlDBMock.ExpectExec(sql).
		WithArgs(keyValue.ZoneID, keyValue.Key, keyValue.Value).
		WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})

	tx, _ := sqlDB.Begin()
	dbOutKeyValue, err := ledger.UpsertKeyValue(tx, keyValue)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(dbOutKeyValue, "key-value should be nil")
	assert.NotNil(err, "error should be not nil")
}

// TestRepoKeyValueWithSuccess tests the retrieval of a key-value pair with success.
func TestRepoKeyValueWithSuccess(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	keyValue := &KeyValue{
		ZoneID: 45645646,
		Key:    "test-key",
		Value:  []byte("test-value"),
	}
	sql := `SELECT zone_id, kv_key, kv_value FROM key_values WHERE zone_id = ? and  kv_key = ?`
	sqlRows := sqlmock.NewRows([]string{"zone_id", "kv_key", "kv_value"}).
		AddRow(keyValue.ZoneID, keyValue.Key, keyValue.Value)

	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(keyValue.ZoneID, keyValue.Key).
		WillReturnRows(sqlRows)

	dbOutKeyValue, err := ledger.KeyValue(sqlDB, keyValue.ZoneID, keyValue.Key)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutKeyValue, "key-value should be not nil")
	assert.Equal(keyValue.Key, dbOutKeyValue.Key, "key is not correct")
	assert.Equal(keyValue.Value, dbOutKeyValue.Value, "value is not correct")
	assert.Nil(err, "error should be nil")
}

// TestRepoKeyValueWithErrors tests the retrieval of a key-value pair with errors.
func TestRepoKeyValueWithErrors(t *testing.T) {
	assert := assert.New(t)
	ledger := Repository{}

	_, sqlDB, _, sqlDBMock := testutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlQuery := `SELECT zone_id, kv_key, kv_value FROM key_values WHERE zone_id = ? and  kv_key = ?`
	zoneID := int64(23423423)
	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sqlQuery)).
		WithArgs(zoneID, "non-existent-key").
		WillReturnError(sql.ErrNoRows)

	dbOutKeyValue, err := ledger.KeyValue(sqlDB, zoneID, "non-existent-key")

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(dbOutKeyValue, "key-value should be nil")
	assert.NotNil(err, "error should be not nil")
}
