package taskengine

import (
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

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
