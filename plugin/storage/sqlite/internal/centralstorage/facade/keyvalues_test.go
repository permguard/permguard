package facade

import (
	"database/sql"
	"regexp"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"

	"github.com/mattn/go-sqlite3"

	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azidbtestutils "github.com/permguard/permguard/plugin/storage/sqlite/internal/centralstorage/facade/testutils"
)

// registerKeyValueForUpsertMocking registers a key-value pair for upsert mocking.
func registerKeyValueForUpsertMocking() (*KeyValue, string, *sqlmock.Rows) {
	keyValue := &KeyValue{
		Key:   "test-key",
		Value: []byte("test-value"),
	}
	var sql string
	sql = `INSERT INTO key_values \(kv_key, kv_value\) VALUES \(\?, \?\) ON CONFLICT\(kv_key\) DO UPDATE SET kv_value = excluded.kv_value`
	sqlRows := sqlmock.NewRows([]string{"kv_key", "kv_value"}).
		AddRow(keyValue.Key, keyValue.Value)
	return keyValue, sql, sqlRows
}

// TestRepoUpsertKeyValueWithInvalidInput tests the upsert of a key-value pair with invalid input.
func TestRepoUpsertKeyValueWithInvalidInput(t *testing.T) {
	assert := assert.New(t)
	repo := Facade{}

	_, sqlDB, _, _ := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	tx, _ := sqlDB.Begin()

	{ // Test with nil key-value
		_, err := repo.UpsertKeyValue(tx, nil)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}

	{ // Test with empty key
		keyValue := &KeyValue{
			Key:   "",
			Value: []byte("test-value"),
		}
		_, err := repo.UpsertKeyValue(tx, keyValue)
		assert.NotNil(err, "error should be not nil")
		assert.True(azerrors.AreErrorsEqual(azerrors.ErrClientParameter, err), "error should be errclientparameter")
	}
}

// TestRepoUpsertKeyValueWithSuccess tests the upsert of a key-value pair with success.
func TestRepoUpsertKeyValueWithSuccess(t *testing.T) {
	assert := assert.New(t)
	repo := Facade{}
	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	keyValue, sql, sqlKeyValueRows := registerKeyValueForUpsertMocking()

	sqlDBMock.ExpectBegin()
	sqlDBMock.ExpectExec(sql).
		WithArgs(keyValue.Key, keyValue.Value).
		WillReturnResult(sqlmock.NewResult(1, 1))

	sqlDBMock.ExpectQuery(`SELECT kv_key, kv_value FROM key_values WHERE kv_key = \?`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlKeyValueRows)

	tx, _ := sqlDB.Begin()
	dbOutKeyValue, err := repo.UpsertKeyValue(tx, keyValue)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutKeyValue, "key-value should be not nil")
	assert.Equal(keyValue.Key, dbOutKeyValue.Key, "key is not correct")
	assert.Equal(keyValue.Value, dbOutKeyValue.Value, "value is not correct")
	assert.Nil(err, "error should be nil")
}

// TestRepoUpsertKeyValueWithErrors tests the upsert of a key-value pair with errors.
func TestRepoUpsertKeyValueWithErrors(t *testing.T) {
	assert := assert.New(t)
	repo := Facade{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	keyValue, sql, _ := registerKeyValueForUpsertMocking()

	sqlDBMock.ExpectBegin()
	sqlDBMock.ExpectExec(sql).
		WithArgs(keyValue.Key, keyValue.Value).
		WillReturnError(sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintUnique})

	tx, _ := sqlDB.Begin()
	dbOutKeyValue, err := repo.UpsertKeyValue(tx, keyValue)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(dbOutKeyValue, "key-value should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageConstraintUnique, err), "error should be errstorageconstraintunique")
}

// TestRepoGetKeyValueWithSuccess tests the retrieval of a key-value pair with success.
func TestRepoGetKeyValueWithSuccess(t *testing.T) {
	assert := assert.New(t)
	repo := Facade{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	keyValue := &KeyValue{
		Key:   "test-key",
		Value: []byte("test-value"),
	}
	sql := `SELECT kv_key, kv_value FROM key_values WHERE kv_key = ?`
	sqlRows := sqlmock.NewRows([]string{"kv_key", "kv_value"}).
		AddRow(keyValue.Key, keyValue.Value)

	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sql)).
		WithArgs(keyValue.Key).
		WillReturnRows(sqlRows)

	dbOutKeyValue, err := repo.GetKeyValue(sqlDB, keyValue.Key)

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.NotNil(dbOutKeyValue, "key-value should be not nil")
	assert.Equal(keyValue.Key, dbOutKeyValue.Key, "key is not correct")
	assert.Equal(keyValue.Value, dbOutKeyValue.Value, "value is not correct")
	assert.Nil(err, "error should be nil")
}

// TestRepoGetKeyValueWithErrors tests the retrieval of a key-value pair with errors.
func TestRepoGetKeyValueWithErrors(t *testing.T) {
	assert := assert.New(t)
	repo := Facade{}

	_, sqlDB, _, sqlDBMock := azidbtestutils.CreateConnectionMocks(t)
	defer sqlDB.Close()

	sqlQuery := `SELECT kv_key, kv_value FROM key_values WHERE kv_key = ?`
	sqlDBMock.ExpectQuery(regexp.QuoteMeta(sqlQuery)).
		WithArgs("non-existent-key").
		WillReturnError(sql.ErrNoRows)

	dbOutKeyValue, err := repo.GetKeyValue(sqlDB, "non-existent-key")

	assert.Nil(sqlDBMock.ExpectationsWereMet(), "there were unfulfilled expectations")
	assert.Nil(dbOutKeyValue, "key-value should be nil")
	assert.NotNil(err, "error should be not nil")
	assert.True(azerrors.AreErrorsEqual(azerrors.ErrStorageNotFound, err), "error should be errstoragenotfound")
}
