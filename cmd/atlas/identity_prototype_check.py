#!/usr/bin/env python3
"""Run the migration identity prototype on a disposable Docker database."""

import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile
import time
from urllib.parse import quote


ATLAS = Path(__file__).resolve().parent
LOCK = "atlas_migrate_execute"
REVISIONS = "atlas_schema_revisions"
IDS = {name: f"550e8400-e29b-41d4-a716-{i:012d}" for i, name in enumerate("0123456789", 1)}
M0 = ("100", "0", "CREATE TABLE items (id INT PRIMARY KEY);\n")
M1 = ("200", "1", "ALTER TABLE items ADD COLUMN feature_one INT;\n")
M2 = ("300", "2", "ALTER TABLE items ADD COLUMN feature_two INT;\n")
M1_REBASED = ("400", *M1[1:])


class CommandError(RuntimeError):
    pass


class Probe:
    def __init__(self, backend, path, binary):
        self.backend = backend
        self.path = path
        self.binary = binary
        self.name = f"atlas-identity-prototype-{backend}-{secrets.token_hex(5)}"
        socket = Path.home() / ".docker/run/docker.sock"
        self.docker = ["docker", "--host", f"unix://{socket if socket.exists() else '/var/run/docker.sock'}"]
        self.password = secrets.token_hex(16) if backend == "mysql" else ""
        self.user = "root" if backend == "mysql" else "root@test"
        self.started = False
        self.checks = 0

    def run(self, args, *, extra_env=None, stdin=None, timeout=25):
        p = subprocess.run(args, cwd=self.path, env={**os.environ, **(extra_env or {})},
                           input=stdin, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        out = self.redact(p.stdout)
        if p.returncode:
            raise CommandError(out.strip())
        return out.strip()

    def redact(self, text):
        return text.replace(self.password, "<scratch-password>") if self.password else text

    def start(self):
        if self.backend == "mysql":
            port, image = 3306, "mysql:8.4"
            config = ["-e", f"MYSQL_ROOT_PASSWORD={self.password}", "-e", "MYSQL_ROOT_HOST=%"]
        else:
            port, image = 2881, "oceanbase/oceanbase-ce:4.3.5-lts"
            storage = self.path / "oceanbase-data"
            storage.mkdir()
            config = ["-e", "MODE=mini", "--mount", f"type=bind,source={storage},target=/root/ob"]
        self.run([*self.docker, "run", "-d", "--pull=never", "--name", self.name,
                  "-p", f"127.0.0.1::{port}", *config, image])
        self.started = True
        self.port = self.run([*self.docker, "port", self.name, f"{port}/tcp"]).rsplit(":", 1)[1]
        deadline = time.monotonic() + (30 if self.backend == "mysql" else 150)
        while True:
            try:
                self.version = self.sql("SELECT VERSION()")
                return
            except CommandError as err:
                running = self.run([*self.docker, "inspect", "--format", "{{.State.Running}}", self.name])
                if running != "true" or time.monotonic() > deadline:
                    raise CommandError(f"scratch {self.backend} did not start\n{err}") from err
                time.sleep(1)

    def close(self):
        if self.started:
            self.run([*self.docker, "rm", "-f", "-v", self.name])

    def sql_args(self, database=None):
        return ["mysql", "--no-defaults", "--no-login-paths", "--protocol=TCP", "--host=127.0.0.1",
                f"--port={self.port}", f"--user={self.user}", "--connect-timeout=2", "--batch", "--skip-column-names",
                *([database] if database else [])]

    def sql(self, text, database=None):
        return self.run(self.sql_args(database), stdin=text + "\n", extra_env={"MYSQL_PWD": self.password})

    def database(self, name):
        self.sql(f"CREATE DATABASE {name};")
        return name

    def directory(self, name, migrations, *, legacy=False):
        path = self.path / name
        path.mkdir()
        for version, identity, body in migrations:
            head = "" if legacy else f"-- atlas:identity {IDS[identity]}\n\n"
            (path / f"{version}_m{identity}.sql").write_bytes((head + body).encode())
        self.run([str(self.binary), "migrate", "hash", "--dir", f"file://{path}"])
        return path

    def apply_args(self, database, directory, *flags, mode="test", revision_schema=None):
        user = quote(self.user, safe="")
        auth = f"{user}:{self.password}" if self.password else user
        return [str(self.binary), "migrate", "apply", "--dir", f"file://{directory}",
                "--url", f"mysql://{auth}@127.0.0.1:{self.port}/{database}",
                "--revisions-schema", revision_schema or database,
                *(["--identity-mode", mode] if mode else []), *flags]

    def apply(self, database, directory, *flags, mode="test", revision_schema=None):
        return self.run(self.apply_args(database, directory, *flags, mode=mode, revision_schema=revision_schema),
                        extra_env={"ATLAS_NO_UPDATE_NOTIFIER": "1"})

    def reject(self, expected, *args, **kwargs):
        try:
            out = self.apply(*args, **kwargs)
        except CommandError as err:
            if expected in str(err):
                return
            raise
        raise AssertionError(f"expected rejection containing {expected!r}, got {out!r}")

    def tables(self, database):
        return self.sql("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME;", database).splitlines()

    def columns(self, database, table):
        return self.sql(f"SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{table}' ORDER BY COLUMN_NAME;", database).splitlines()

    def facts(self, database):
        result = self.sql(f"SELECT version, description, type, applied, total, executed_at, execution_time, hash, COALESCE(error,''), operator_version FROM {REVISIONS} ORDER BY version;", database)
        return {line.split("\t", 1)[0]: line.split("\t", 1)[1] for line in result.splitlines()}

    def state(self, database):
        result = self.sql(f"SELECT version, migration_id, content_hash, identity_history FROM {REVISIONS} ORDER BY version;", database)
        return {v: {"id": i, "hash": h, "events": None if a == "NULL" else json.loads(a)}
                for v, i, h, a in (line.split("\t", 3) for line in result.splitlines())}

    def fault(self, database, condition, message):
        self.sql(f"""DELIMITER //
CREATE TRIGGER refuse_revision BEFORE UPDATE ON {REVISIONS} FOR EACH ROW
BEGIN
  IF {condition} THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '{message}';
  END IF;
END//
DELIMITER ;""", database)

    def checked(self, title, condition, state=None):
        if not condition:
            raise AssertionError(f"{title}: {state}")
        self.checks += 1
        print(json.dumps({"check": title, "state": state}, ensure_ascii=False), flush=True)


def walkthrough(p):
    base = p.directory("base", [M0])
    all_test = p.directory("all_test", [M0, M1, M2])
    main = p.directory("main", [M0, M2])
    release = p.directory("release", [M0, M2, M1_REBASED])
    legacy_base = p.directory("legacy_base", [M0], legacy=True)
    legacy_test = p.directory("legacy_test", [M0, M1, M2], legacy=True)
    legacy_main = p.directory("legacy_main", [M0, M2], legacy=True)
    test, prod = p.database("play_test"), p.database("play_prod")

    preview = p.apply(test, all_test, "--dry-run")
    p.checked("empty database preview is read-only", preview.count("pending ") == 3 and not p.tables(test), preview)
    fresh = p.database("play_fresh")
    out = p.apply(fresh, all_test, "--tx-mode", "all")
    p.checked("all transaction mode binds identity history for multiple files", out.count("execute ") == 3
              and {row["id"] for row in p.state(fresh).values()} == {IDS[k] for k in "012"}, p.state(fresh))
    p.apply(test, legacy_test, mode="")
    p.apply(prod, legacy_base, mode="")
    before = p.facts(test)
    p.reject("missing header-bearing file", test, main, "--identity-import-from", str(legacy_test))
    p.reject("legacy evidence does not match", test, all_test, "--identity-import-from", str(legacy_main))
    preview = p.apply(test, all_test, "--identity-import-from", str(legacy_test), "--dry-run")
    p.checked("legacy import preview and evidence gate", preview.count("import ") == 3 and p.facts(test) == before
              and "migration_id" not in p.columns(test, REVISIONS), preview)

    p.fault(test, "NEW.version = '200'", "prototype import write refused")
    p.reject("prototype import write refused", test, all_test, "--identity-import-from", str(legacy_test))
    after_fault = p.state(test)
    p.checked("schema expansion survives and the import transaction rolls back", set(after_fault) == set(before)
              and all(row["id"] == "NULL" for row in after_fault.values()) and p.facts(test) == before, after_fault)
    p.reject("requires identity import", test, all_test)
    p.sql("DROP TRIGGER refuse_revision;", test)
    p.apply(test, all_test, "--identity-import-from", str(legacy_test))
    adopted = p.state(test)
    p.checked("retry imports evidence without rewriting execution facts", p.facts(test) == before
              and adopted["200"]["id"] == IDS["1"] and adopted["200"]["events"][0]["action"] == "import", adopted)
    p.checked("repeated import is idempotent", p.apply(test, all_test, "--identity-import-from", str(legacy_test)) == ""
              and p.state(test) == adopted)
    p.reject("identity history requires", test, legacy_test, "--dry-run", mode="")
    p.checked("plain apply preserves upgraded history", p.state(test) == adopted)

    out = p.apply(test, main)
    p.checked("test branch without M1 retains structure and successful history", "retain 200" in out and "execute " not in out
              and p.state(test) == adopted and "feature_one" in p.columns(test, "items"), out)
    out = p.apply(test, all_test)
    p.checked("test branch returning with the original M1 skips it", "skip 200" in out and "execute " not in out, out)
    p.reject("approved identity mapping", test, release)
    out = p.apply(test, release, "--identity-remap", "200=400", "--dry-run")
    p.checked("remap preview preserves upgraded rows and columns", "remap 200 400" in out and p.state(test) == adopted, out)
    p.fault(test, "NEW.version = '400'", "prototype remap refused")
    p.reject("prototype remap refused", test, release, "--identity-remap", "200=400")
    p.checked("failed remap leaves execution facts and audit intact", p.state(test) == adopted and p.facts(test) == before)
    p.sql("DROP TRIGGER refuse_revision;", test)
    out = p.apply(test, release, "--identity-remap", "200=400")
    aligned = p.state(test)
    p.checked("test rebase remaps the original history without executing M1", "execute " not in out and "200" not in aligned
              and aligned["400"]["hash"] == adopted["200"]["hash"] and p.facts(test)["400"] == before["200"]
              and aligned["400"]["events"][-1]["from"] == "200", aligned)
    p.apply(test, main)
    out = p.apply(test, all_test)
    p.checked("old branch returning after rebase leaves the aligned revision in place",
              "skip 200" in out and "execute " not in out and p.state(test) == aligned, out)

    p.apply(prod, all_test, "--identity-import-from", str(legacy_base), mode="production")
    p.checked("production import records only its actually applied M0", set(p.state(prod)) == {"100"}, p.state(prod))
    out = p.apply(prod, main, mode="production")
    p.checked("selective release executes M2 on the production baseline", "execute 300" in out and set(p.state(prod)) == {"100", "300"}
              and p.columns(prod, "items") == ["feature_two", "id"], p.state(prod))
    p.reject("must follow 300", prod, all_test, mode="production")
    out = p.apply(prod, release, "--tx-mode", "all", mode="production")
    again = p.apply(prod, release, mode="production")
    p.checked("later frozen release executes rebased M1 once", "execute 400" in out and "execute " not in again
              and p.state(prod)["400"]["id"] == aligned["400"]["id"]
              and p.state(prod)["400"]["hash"] == aligned["400"]["hash"]
              and p.columns(prod, "items") == p.columns(test, "items"), p.state(prod))

    changed = p.directory("changed", [M0, ("200", "1", M1[2] + "-- different bytes\n"), M2])
    p.reject("content changed", test, changed)
    same_sql = p.directory("same_sql", [M0, M2, M1_REBASED, ("500", "3", M1[2])])
    out = p.apply(test, same_sql, "--dry-run")
    p.checked("content validation and distinct identity with the same business SQL", "pending 500" in out and p.state(test) == aligned, out)
    late = p.database("play_late")
    high = ("300", "4", "CREATE TABLE high_version (id INT);\n")
    low = ("100", "5", "CREATE TABLE late_version (id INT);\n")
    p.apply(late, p.directory("high", [high]))
    out = p.apply(late, p.directory("high_and_low", [low, high]), "--tx-mode", "none")
    p.checked("test executes a new identity earlier than all successful versions", "execute 100" in out
              and {"late_version", "high_version"} <= set(p.tables(late)), p.state(late))

    faulty = ("500", "6", "ALTER TABLE high_version ADD COLUMN committed_before_history INT;\n")
    fault_dir = p.directory("fault", [low, high, faulty])
    p.fault(late, "NEW.version = '500'", "prototype progress write refused")
    p.reject("prototype progress write refused", late, fault_dir)
    progress = p.sql(f"SELECT CONCAT(applied, '/', total) FROM {REVISIONS} WHERE version = '500';", late)
    p.sql("DROP TRIGGER refuse_revision;", late)
    p.reject("needs history and schema review before retry", late, fault_dir)
    p.checked("committed DDL with failed history progress blocks automatic retry", progress == "0/1"
              and "committed_before_history" in p.columns(late, "high_version"), {"history": progress, "columns": p.columns(late, "high_version")})

    shared = p.database("play_shared")
    service_a, service_b = p.database("play_service_a"), p.database("play_service_b")
    a = p.directory("service_a", [("100", "7", "CREATE TABLE service_a (id INT);\n")])
    b = p.directory("service_b", [("100", "8", "CREATE TABLE service_b (id INT);\n")])
    p.apply(shared, a, revision_schema=service_a)
    p.apply(shared, b, "--allow-dirty", revision_schema=service_b)
    p.checked("services sharing business DB keep separate same-number revisions", p.tables(shared) == ["service_a", "service_b"]
              and p.state(service_a)["100"]["id"] == IDS["7"] and p.state(service_b)["100"]["id"] == IDS["8"])
    locks(p, base, test, all_test, legacy_test)


def locks(p, base, imported_database, header_directory, legacy_directory):
    database = p.database("play_lock")
    holder = subprocess.Popen([*p.sql_args(database), "--execute", f"SELECT GET_LOCK('{LOCK}',0); SELECT SLEEP(5);"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                              env={**os.environ, "MYSQL_PWD": p.password})
    try:
        until = time.monotonic() + 3
        while p.sql(f"SELECT IS_USED_LOCK('{LOCK}') IS NOT NULL;") != "1":
            if holder.poll() is not None or time.monotonic() > until:
                raise AssertionError("scratch connection did not acquire the lock")
            time.sleep(0.1)
        p.reject("acquiring database lock", database, base, "--lock-timeout", "1s")
        p.reject("acquiring database lock", imported_database, header_directory, "--lock-timeout", "1s",
                 "--identity-import-from", str(legacy_directory))
        p.checked("apply and identity import both contend for the Atlas lock", not p.tables(database))
    finally:
        holder.communicate(timeout=7)

    waiting = p.directory("wait_in_migration", [("100", "9", "SELECT SLEEP(15);\nCREATE TABLE after_lock_loss (id INT);\n")])
    worker = subprocess.Popen(p.apply_args(database, waiting, "--tx-mode", "none"), cwd=p.path, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              env={**os.environ, "ATLAS_NO_UPDATE_NOTIFIER": "1"})
    try:
        until = time.monotonic() + 8
        while True:
            owner = p.sql(f"SELECT IS_USED_LOCK('{LOCK}');")
            started = REVISIONS in p.tables(database) and p.sql(f"SELECT COUNT(*) FROM {REVISIONS};", database) == "1"
            if owner.isdecimal() and started:
                break
            if worker.poll() is not None or time.monotonic() > until:
                raise AssertionError("migration did not reach the first statement")
            time.sleep(0.1)
        p.sql(f"KILL CONNECTION {int(owner)};")
        output = p.redact(worker.communicate(timeout=8)[0])
        p.reject("needs history and schema review before retry", database, waiting)
        p.checked("losing the lock session stops later DDL and leaves observable progress", worker.returncode != 0
                  and "after_lock_loss" not in p.tables(database) and p.sql(f"SELECT IS_USED_LOCK('{LOCK}');") == "NULL", output)
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.communicate()


def main():
    def terminate(*_):
        raise SystemExit(143)

    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backend", choices=("mysql", "oceanbase"))
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="atlas-identity-prototype-") as path:
        path = Path(path)
        binary = args.binary.resolve() if args.binary else path / "atlas"
        if not args.binary:
            subprocess.run(["go", "build", "-mod=readonly", "-o", str(binary), "."], cwd=ATLAS,
                           env={**os.environ, "GOWORK": "off"}, check=True)
        probe = Probe(args.backend, path, binary)
        try:
            probe.start()
            print(json.dumps({"backend": args.backend, "version": probe.version}), flush=True)
            walkthrough(probe)
            print(json.dumps({"passed": probe.checks, "backend": args.backend}), flush=True)
        except Exception:
            if probe.started and not hasattr(probe, "version"):
                print(probe.run([*probe.docker, "logs", "--tail", "35", probe.name]), flush=True)
            raise
        finally:
            probe.close()


if __name__ == "__main__":
    main()
