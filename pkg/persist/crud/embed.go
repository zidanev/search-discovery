// Package crud implement data to object struct and object-relational mapping.
// using ent framework makes it easy to build and maintain with large data-models.
// Schema As Code - model any database schema as Go objects.
// Multi Storage Driver - supports MySQL, MariaDB, TiDB, PostgresSQL, CockroachDB, SQLite and Gremlin.
// # This manifest was generated by ymir. DO NOT EDIT.
package crud

import (
	"embed"
	"os"
	"path"
	"path/filepath"
)

//go:embed all:migrations
var embeddedMigrations embed.FS

// embedWriteTemp writes the embedded migrations to a temporary directory.
// It returns an error and a cleanup function. The cleanup function
// should be called when the migrations are no longer needed.
func embedWriteTemp(temp, dialect string) error {
	err := os.MkdirAll(temp, 0755)
	if err != nil {
		return err
	}

	basePath := path.Join("migrations", dialect)
	fsDir, err := embeddedMigrations.ReadDir(basePath)
	if err != nil {
		return err
	}

	for _, f := range fsDir {
		if f.IsDir() {
			continue
		}

		b, err := embeddedMigrations.ReadFile(path.Join(basePath, f.Name()))
		if err != nil {
			return err
		}

		err = os.WriteFile(filepath.Join(temp, f.Name()), b, 0600)
		if err != nil {
			return err
		}
	}
	return nil
}