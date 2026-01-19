package skyforge

import (
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// isMissingDBRelation returns true when a SQL query failed because a table/view
// does not exist (typically because migrations haven't been applied yet).
func isMissingDBRelation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// undefined_table
		return pgErr.Code == "42P01"
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "relation") && strings.Contains(msg, "does not exist")
}

// isMissingDBColumn returns true when a SQL query failed because a column does
// not exist (typically because migrations haven't been applied yet).
func isMissingDBColumn(err error, columnName string) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// undefined_column
		if pgErr.Code != "42703" {
			return false
		}
		if strings.TrimSpace(columnName) == "" {
			return true
		}
		return strings.EqualFold(pgErr.ColumnName, strings.TrimSpace(columnName)) ||
			strings.Contains(strings.ToLower(pgErr.Message), strings.ToLower(strings.TrimSpace(columnName)))
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "does not exist") {
		return false
	}
	if strings.TrimSpace(columnName) == "" {
		return strings.Contains(msg, "column")
	}
	return strings.Contains(msg, "column") && strings.Contains(msg, strings.ToLower(strings.TrimSpace(columnName)))
}
