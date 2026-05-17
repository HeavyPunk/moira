package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/moira-alert/moira/database/postgresql/migrations"
)

func (conn *DbConnector) ApplyMigrations(ctx context.Context) error {
	migrationsToApply := []migrations.Migration{
		migrations.Init_01(),
	}

	conn.db.Master()

	lastMigrationNumber, err := conn.getLastMigrationNumber(ctx)
	if err != nil {
		return err
	}

	slices.SortFunc(migrationsToApply, func(a, b migrations.Migration) int {
		return int(a.Number - b.Number)
	})

	lastMigrationIndex := slices.IndexFunc(migrationsToApply, func(m migrations.Migration) bool {
		// NOTE: If lastMigrationNumber == 0 then none of migrations were applied yet, so took the first one.
		return lastMigrationNumber == 0 || m.Number == lastMigrationNumber
	})
	if lastMigrationIndex == -1 {
		return fmt.Errorf("last applied migration in database with number %d not found", lastMigrationNumber)
	}

	for i := range migrationsToApply[lastMigrationIndex+1:] {
		// TODO: add logging
		migration := migrationsToApply[i]

		err := conn.applyMigration(ctx, migration)
		if err != nil {
			return fmt.Errorf("error on applying migration %d: %w", migration.Number, err)
		}
	}

	return nil
}

func (conn *DbConnector) applyMigration(ctx context.Context, migration migrations.Migration) error {
	_, err := conn.db.Master().ExecContext(ctx, migration.ForwardSQL)
	return err
}

func (conn *DbConnector) getLastMigrationNumber(ctx context.Context) (int64, error) {
	query := "SELECT number FROM migrations ORDER BY applied_at LIMIT 1"

	var lastMigrationNumber int64

	err := conn.db.Master().QueryRowContext(ctx, query).Scan(&lastMigrationNumber)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return -1, fmt.Errorf("error on getting last migration number: %w", err)
	}

	return lastMigrationNumber, nil
}
