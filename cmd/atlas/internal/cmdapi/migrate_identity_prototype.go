// Copyright 2021-present The Atlas Authors. All rights reserved.
// This source code is licensed under the Apache 2.0 license found
// in the LICENSE file in the root directory of this source tree.

package cmdapi

// This prototype checks branch round trips and selective releases against scratch databases.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	cmdmigrate "ariga.io/atlas/cmd/atlas/internal/migrate"
	"ariga.io/atlas/cmd/atlas/internal/migrate/ent/revision"
	"ariga.io/atlas/sql/migrate"
	"ariga.io/atlas/sql/mysql"
	"ariga.io/atlas/sql/schema"
	"ariga.io/atlas/sql/sqlclient"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

const identityHeader = "-- atlas:identity "

type identityFile struct {
	*migrate.LocalFile
	id, digest string
	body       []byte
}

type identityRevision struct {
	*migrate.Revision
	id, digest string
	audit      []identityEvent
}

type identityEvent struct {
	Action           string    `json:"action"`
	At               time.Time `json:"at"`
	From             string    `json:"from,omitempty"`
	To               string    `json:"to,omitempty"`
	OldDirectoryHash string    `json:"old_directory_hash,omitempty"`
	OldContentHash   string    `json:"old_content_hash,omitempty"`
	NewContentHash   string    `json:"new_content_hash,omitempty"`
}

type identityChange struct {
	row  *identityRevision
	file identityFile
}

type identityStore struct {
	client *sqlclient.Client
	conn   *sql.Conn
	driver migrate.Driver
	ident  *migrate.TableIdent
	table  string
}

func migrateIdentityPrototype(cmd *cobra.Command, client *sqlclient.Client, dir migrate.Dir, flags migrateApplyFlags, count int) (err error) {
	if flags.identityMode != "test" && flags.identityMode != "production" {
		return errors.New("identity mode requires test or production")
	}
	if _, ok := dir.(*migrate.LocalDir); client.Name != mysql.DriverName || !ok || client.URL.Schema == "" {
		return errors.New("identity prototype requires a local Atlas directory and a database-scoped mysql URL")
	}
	if flags.baselineVersion != "" || flags.execOrder != execOrderLinear || flags.logFormat != "" {
		return errors.New("identity prototype uses its own ordering, history checks, and text output")
	}
	if flags.identityImport != "" && (len(flags.identityRemap) != 0 || count != 0) {
		return errors.New("identity import takes the complete history as input")
	}
	switch flags.txMode {
	case txModeFile, txModeAll, txModeNone:
	default:
		return fmt.Errorf("unknown transaction mode %q", flags.txMode)
	}
	files, err := identityFiles(dir)
	if err != nil {
		return err
	}
	// Plan and execute from the same validated bytes.
	snapshot := &migrate.MemDir{}
	for _, f := range files {
		if err := snapshot.WriteFile(f.Name(), f.Bytes()); err != nil {
			return err
		}
	}
	if sum, err := fs.ReadFile(dir, migrate.HashFileName); err == nil {
		if err := snapshot.WriteFile(migrate.HashFileName, sum); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := migrate.Validate(snapshot); err != nil {
		return err
	}
	ctx := cmd.Context()
	// The named lock and all mutations share a session. Losing the session
	// stops writes without acquiring a new connection behind the lock.
	conn, err := client.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	drv, err := mysql.Open(conn)
	if err != nil {
		return err
	}
	unlock, err := drv.Lock(ctx, applyLockValue, flags.lockTimeout)
	if err != nil {
		return fmt.Errorf("acquiring database lock: %w", err)
	}
	defer func() { err = errors.Join(err, unlock()) }()
	if err := checkRevisionSchemaClarity(cmd, client, flags.revisionSchema); err != nil {
		return err
	}
	s := &identityStore{
		client: client, conn: conn, driver: drv,
		ident: &migrate.TableIdent{Schema: revisionSchemaName(client, flags.revisionSchema), Name: revision.Table},
	}
	s.table = "`" + strings.ReplaceAll(s.ident.Schema, "`", "``") + "`.`" + s.ident.Name + "`"
	var exists int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?", s.ident.Schema).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return fmt.Errorf("create history schema %q before running the prototype", s.ident.Schema)
	}
	tableExists, upgraded, err := s.status(ctx)
	if err != nil {
		return err
	}
	rows, err := s.history(ctx, tableExists, upgraded)
	if err != nil {
		return err
	}
	if flags.identityImport != "" {
		if !tableExists {
			return errors.New("identity import requires an existing history table")
		}
		return s.importHistory(cmd, flags, rows, files, upgraded)
	}
	if len(rows) == 0 {
		var dirty *migrate.NotCleanError
		if err := drv.CheckClean(ctx, s.ident); err != nil && (!errors.As(err, &dirty) || !flags.allowDirty) {
			return err
		}
	}
	pending, changes, err := identityPlan(cmd, flags, rows, files)
	if err != nil {
		return err
	}
	if count > 0 && count < len(pending) {
		pending = pending[:count]
	}
	for _, f := range pending {
		fmt.Fprintf(cmd.OutOrStdout(), "pending %s %s\n", f.Version(), f.id)
	}
	if flags.dryRun || len(pending)+len(changes) == 0 {
		return nil
	}
	if !upgraded {
		if err := s.upgrade(ctx, tableExists); err != nil {
			return err
		}
	}
	if len(changes) != 0 {
		if err := s.remap(ctx, changes); err != nil {
			return err
		}
	}
	return s.execute(ctx, cmd, snapshot, flags, pending)
}

func identityFiles(dir migrate.Dir) ([]identityFile, error) {
	files, err := dir.Files()
	if err != nil {
		return nil, err
	}
	ids, versions := make(map[string]bool), make(map[string]bool)
	result := make([]identityFile, 0, len(files))
	for _, f := range files {
		lf := f.(*migrate.LocalFile)
		head, body, ok := bytes.Cut(f.Bytes(), []byte("\n\n"))
		id, hasHeader := strings.CutPrefix(string(head), identityHeader)
		u, uerr := uuid.Parse(id)
		if !ok || !hasHeader || uerr != nil || u.String() != id || len(lf.Directive("identity")) != 1 {
			return nil, fmt.Errorf("%s requires one canonical UUID in its identity header", f.Name())
		}
		// An identity header must not change another file directive's scope.
		stripped := migrate.NewLocalFile(f.Name(), body)
		if stripped.IsCheckpoint() || !identityVersion(f.Version()) {
			return nil, fmt.Errorf("unsupported migration file %s", f.Name())
		}
		for _, directive := range []string{"identity", "sum", "delimiter", "txmode"} {
			if len(stripped.Directive(directive)) != 0 {
				return nil, fmt.Errorf("unsupported file directive %s in %s", directive, f.Name())
			}
		}
		if ids[id] || versions[f.Version()] {
			return nil, fmt.Errorf("duplicate identity or version in %s", f.Name())
		}
		ids[id], versions[f.Version()] = true, true
		result = append(result, identityFile{LocalFile: lf, id: id, digest: identityDigest(f.Bytes()), body: body})
	}
	return result, nil
}

func identityVersion(version string) bool {
	return version != "" && strings.Trim(version, "0123456789") == ""
}

func identityDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s *identityStore) status(ctx context.Context) (exists, upgraded bool, err error) {
	var columns, identityColumns int
	err = s.conn.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(COLUMN_NAME IN ('migration_id', 'content_hash', 'identity_history')), 0)
FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?`, s.ident.Schema, s.ident.Name).Scan(&columns, &identityColumns)
	if err == nil && identityColumns != 0 && identityColumns != 3 {
		err = errors.New("identity history schema upgrade is incomplete")
	}
	return columns != 0, identityColumns == 3, err
}

func (s *identityStore) legacy(ctx context.Context, drv migrate.Driver) (*cmdmigrate.EntRevisions, error) {
	bound := *s.client
	bound.Driver = drv
	return cmdmigrate.NewEntRevisions(ctx, &bound, cmdmigrate.WithSchema(s.ident.Schema))
}

func (s *identityStore) history(ctx context.Context, exists, upgraded bool) ([]*identityRevision, error) {
	if !exists {
		return nil, nil
	}
	legacy, err := s.legacy(ctx, s.driver)
	if err != nil {
		return nil, err
	}
	revs, err := legacy.ReadRevisions(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]*identityRevision, 0, len(revs))
	for _, r := range revs {
		if r.Type != migrate.RevisionTypeExecute || r.Applied != r.Total || r.Error != "" || len(r.PartialHashes) != 0 || !identityVersion(r.Version) {
			return nil, fmt.Errorf("revision %s (%d/%d, %s) needs history and schema review before retry", r.Version, r.Applied, r.Total, r.Type)
		}
		row := &identityRevision{Revision: r}
		if upgraded {
			var id, digest, audit sql.NullString
			if err := s.conn.QueryRowContext(ctx, "SELECT migration_id, content_hash, identity_history FROM "+s.table+" WHERE version = ?", r.Version).Scan(&id, &digest, &audit); err != nil {
				return nil, err
			}
			if id.Valid != digest.Valid || id.Valid != audit.Valid {
				return nil, fmt.Errorf("incomplete identity metadata for %s", r.Version)
			}
			if audit.Valid {
				u, idErr := uuid.Parse(id.String)
				hash, hashErr := hex.DecodeString(digest.String)
				if idErr != nil || u.String() != id.String || hashErr != nil || len(hash) != sha256.Size {
					return nil, fmt.Errorf("invalid identity metadata for %s", r.Version)
				}
				row.id, row.digest = id.String, digest.String
				if err := json.Unmarshal([]byte(audit.String), &row.audit); err != nil {
					return nil, fmt.Errorf("identity audit for %s: %w", r.Version, err)
				}
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func identityPlan(cmd *cobra.Command, flags migrateApplyFlags, rows []*identityRevision, files []identityFile) ([]identityFile, []identityChange, error) {
	byID, byVersion := make(map[string]*identityRevision), make(map[string]*identityRevision)
	var latest string
	for _, row := range rows {
		if row.id == "" || row.digest == "" {
			return nil, nil, fmt.Errorf("revision %s requires identity import", row.Version)
		}
		if byID[row.id] != nil {
			return nil, nil, fmt.Errorf("duplicate history identity %s", row.id)
		}
		byID[row.id], byVersion[row.Version] = row, row
		if row.Version > latest {
			latest = row.Version
		}
	}
	remaps := make(map[string]string)
	for _, mapping := range flags.identityRemap {
		from, to, ok := strings.Cut(mapping, "=")
		if !ok || !identityVersion(from) || !identityVersion(to) || from >= to || remaps[to] != "" {
			return nil, nil, fmt.Errorf("invalid identity mapping %q", mapping)
		}
		remaps[to] = from
	}
	var pending []identityFile
	var changes []identityChange
	seen := make(map[string]bool)
	for _, file := range files {
		v := file.Version()
		seen[file.id] = true
		if occupied := byVersion[v]; occupied != nil && occupied.id != file.id {
			return nil, nil, fmt.Errorf("version %s belongs to another identity", v)
		}
		row := byID[file.id]
		switch {
		case row == nil:
			if flags.identityMode == "production" && v <= latest {
				return nil, nil, fmt.Errorf("production migration %s must follow %s", v, latest)
			}
			pending = append(pending, file)
		case row.digest != file.digest:
			return nil, nil, fmt.Errorf("content changed for applied identity %s", file.id)
		case flags.identityMode == "production" && v != row.Version:
			return nil, nil, fmt.Errorf("production history requires published version %s for %s", row.Version, file.id)
		case v > row.Version:
			if remaps[v] != row.Version {
				return nil, nil, fmt.Errorf("migration %s requires an approved identity mapping %s=%s", file.id, row.Version, v)
			}
			changes = append(changes, identityChange{row, file})
			fmt.Fprintf(cmd.OutOrStdout(), "remap %s %s %s\n", row.Version, v, file.id)
		default:
			fmt.Fprintf(cmd.OutOrStdout(), "skip %s %s\n", v, file.id)
		}
	}
	for _, row := range rows {
		if !seen[row.id] {
			if flags.identityMode == "production" {
				return nil, nil, fmt.Errorf("published migration %s is missing", row.Version)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "retain %s %s\n", row.Version, row.id)
		}
	}
	return pending, changes, nil
}

func (s *identityStore) importHistory(cmd *cobra.Command, flags migrateApplyFlags, rows []*identityRevision, files []identityFile, upgraded bool) error {
	old, err := migrate.NewLocalDir(flags.identityImport)
	if err != nil {
		return err
	}
	if err := migrate.Validate(old); err != nil {
		return fmt.Errorf("legacy directory: %w", err)
	}
	originals, err := old.Files()
	if err != nil {
		return err
	}
	sum, err := migrate.NewHashFile(originals)
	if err != nil {
		return err
	}
	oldByName, newByVersion := make(map[string]migrate.File), make(map[string]identityFile)
	for _, f := range originals {
		oldByName[f.Name()] = f
	}
	for _, f := range files {
		newByVersion[f.Version()] = f
	}
	var imports []identityChange
	for _, row := range rows {
		f, ok := newByVersion[row.Version]
		if !ok {
			return fmt.Errorf("missing header-bearing file for revision %s", row.Version)
		}
		original := oldByName[f.Name()]
		oldHash, err := sum.SumByName(f.Name())
		if err != nil || original == nil || oldHash != row.Hash || !bytes.Equal(original.Bytes(), f.body) {
			return fmt.Errorf("legacy evidence does not match revision %s", row.Version)
		}
		if row.id != "" {
			if row.id != f.id || row.digest != f.digest {
				return fmt.Errorf("conflicting imported identity for %s", row.Version)
			}
			continue
		}
		fmt.Fprintf(cmd.OutOrStdout(), "import %s %s %s %s\n", row.Version, f.id, identityDigest(f.body), f.digest)
		imports = append(imports, identityChange{row, f})
	}
	if flags.dryRun || len(imports) == 0 {
		return nil
	}
	ctx := cmd.Context()
	if !upgraded {
		if err := s.upgrade(ctx, true); err != nil {
			return err
		}
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		for _, ch := range imports {
			f, row := ch.file, ch.row
			audit, err := json.Marshal([]identityEvent{{
				Action: "import", At: time.Now().UTC(), To: row.Version, OldDirectoryHash: row.Hash,
				OldContentHash: identityDigest(f.body), NewContentHash: f.digest,
			}})
			if err != nil {
				return err
			}
			res, err := tx.ExecContext(ctx, "UPDATE "+s.table+" SET migration_id = ?, content_hash = ?, identity_history = ? WHERE version = ? AND hash = ? AND migration_id IS NULL", f.id, f.digest, string(audit), row.Version, row.Hash)
			if err := identityUpdated(res, err); err != nil {
				return fmt.Errorf("import %s: %w", row.Version, err)
			}
		}
		return nil
	})
}

const identityColumns = `ADD COLUMN migration_id varchar(36) NULL,
ADD COLUMN content_hash char(64) NULL,
ADD COLUMN identity_history longtext NULL,
ADD UNIQUE INDEX atlas_migration_id (migration_id)`

func (s *identityStore) upgrade(ctx context.Context, exists bool) error {
	if exists {
		_, err := s.conn.ExecContext(ctx, "ALTER TABLE "+s.table+" "+identityColumns)
		return err
	}
	_, err := s.conn.ExecContext(ctx, "CREATE TABLE "+s.table+` (
version varchar(255) PRIMARY KEY, description varchar(255) NOT NULL, type bigint unsigned NOT NULL,
applied bigint NOT NULL, total bigint NOT NULL, executed_at datetime(6) NOT NULL, execution_time bigint NOT NULL,
error longtext NULL, error_stmt longtext NULL, hash varchar(255) NOT NULL, partial_hashes json NULL,
operator_version varchar(255) NOT NULL, migration_id varchar(36) NULL, content_hash char(64) NULL,
identity_history longtext NULL, UNIQUE KEY atlas_migration_id (migration_id)) ENGINE=InnoDB`)
	return err
}

func (s *identityStore) remap(ctx context.Context, changes []identityChange) error {
	return s.transaction(ctx, func(tx *sql.Tx) error {
		for _, ch := range changes {
			f, row := ch.file, ch.row
			audit, err := json.Marshal(append(row.audit, identityEvent{Action: "remap", At: time.Now().UTC(), From: row.Version, To: f.Version(), NewContentHash: f.digest}))
			if err != nil {
				return err
			}
			res, err := tx.ExecContext(ctx, "UPDATE "+s.table+" SET version = ?, identity_history = ? WHERE version = ? AND migration_id = ? AND content_hash = ?", f.Version(), string(audit), row.Version, f.id, f.digest)
			if err := identityUpdated(res, err); err != nil {
				return fmt.Errorf("remap %s: %w", row.Version, err)
			}
		}
		return nil
	})
}

func identityUpdated(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		err = errors.New("history changed while applying an identity update")
	}
	return err
}

func (s *identityStore) transaction(ctx context.Context, apply func(*sql.Tx) error) error {
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := apply(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *identityStore) execute(ctx context.Context, cmd *cobra.Command, dir migrate.Dir, flags migrateApplyFlags, files []identityFile) error {
	execute := func(q schema.ExecQuerier, drv migrate.Driver, file identityFile) error {
		revs, err := s.legacy(ctx, drv)
		if err != nil {
			return err
		}
		writer := &identityWriter{RevisionReadWriter: revs, q: q, table: s.table, file: file}
		ex, err := migrate.NewExecutor(drv, dir, writer, migrate.WithOperatorVersion(operatorVersion()))
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "execute %s %s\n", file.Version(), file.id)
		return ex.Execute(ctx, file.LocalFile)
	}
	if flags.txMode == txModeAll && len(files) != 0 {
		return s.transaction(ctx, func(tx *sql.Tx) error {
			drv, err := mysql.Open(tx)
			if err != nil {
				return err
			}
			for _, file := range files {
				if err := execute(tx, drv, file); err != nil {
					return err
				}
			}
			return nil
		})
	}
	for _, file := range files {
		switch flags.txMode {
		case txModeFile:
			if err := s.transaction(ctx, func(tx *sql.Tx) error {
				drv, err := mysql.Open(tx)
				if err != nil {
					return err
				}
				return execute(tx, drv, file)
			}); err != nil {
				return err
			}
		case txModeNone:
			if err := execute(s.conn, s.driver, file); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown transaction mode %q", flags.txMode)
		}
	}
	return nil
}

type identityWriter struct {
	migrate.RevisionReadWriter
	q       schema.ExecQuerier
	table   string
	file    identityFile
	started bool
}

func (w *identityWriter) WriteRevision(ctx context.Context, rev *migrate.Revision) error {
	var partial any
	if len(rev.PartialHashes) != 0 {
		data, err := json.Marshal(rev.PartialHashes)
		if err != nil {
			return err
		}
		partial = string(data)
	}
	if !w.started {
		_, err := w.q.ExecContext(ctx, "INSERT INTO "+w.table+` (version, description, type, applied, total, executed_at, execution_time,
error, error_stmt, hash, partial_hashes, operator_version, migration_id, content_hash, identity_history)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]')`, rev.Version, rev.Description, uint(rev.Type), rev.Applied, rev.Total,
			rev.ExecutedAt, int64(rev.ExecutionTime), rev.Error, rev.ErrorStmt, rev.Hash, partial, rev.OperatorVersion, w.file.id, w.file.digest)
		w.started = err == nil
		return err
	}
	res, err := w.q.ExecContext(ctx, "UPDATE "+w.table+` SET applied = ?, execution_time = ?, error = ?, error_stmt = ?, partial_hashes = ?
WHERE version = ? AND migration_id = ? AND content_hash = ?`, rev.Applied, int64(rev.ExecutionTime), rev.Error, rev.ErrorStmt,
		partial, rev.Version, w.file.id, w.file.digest)
	return identityUpdated(res, err)
}
