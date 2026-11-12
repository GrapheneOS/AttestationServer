package app.attestation.server;

import app.attestation.server.sqlite.SQLiteConnection;
import app.attestation.server.sqlite.SQLiteException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static app.attestation.server.TestDatabases.queryLong;
import static app.attestation.server.TestDatabases.queryString;
import static app.attestation.server.TestDatabases.queryStrings;
import static app.attestation.server.TestDatabases.schema;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.sqlite.jni.capi.CApi.SQLITE_CONSTRAINT_FOREIGNKEY;

class DatabaseSetupTest {
    @TempDir
    Path dir;

    @Test
    void freshAttestationDatabase() throws Exception {
        try (final SQLiteConnection conn = TestDatabases.attestation(dir)) {
            assertEquals(16, queryLong(conn, "PRAGMA user_version"));
            assertEquals(List.of("Accounts", "Attestations", "Configuration", "Devices", "EmailAddresses", "Sessions",
                    "sqlite_sequence"), queryStrings(conn, "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name"));
            assertEquals(List.of("Accounts_loginTime", "Attestations_fingerprint_id", "Devices_deletionTime",
                    "Devices_userId_verifiedTimeFirst", "Devices_userId_verifiedTimeLast_deletionTimeNull",
                    "Devices_verifiedTimeLast_deletionTimeNull", "Sessions_expiryTime", "Sessions_userId"),
                    queryStrings(conn, "SELECT name FROM sqlite_schema WHERE type = 'index' AND sql IS NOT NULL ORDER BY name"));
            assertEquals("ok", queryString(conn, "PRAGMA integrity_check"));
        }
    }

    @Test
    void freshSamplesDatabase() throws Exception {
        try (final SQLiteConnection conn = TestDatabases.samples(dir)) {
            assertEquals(1, queryLong(conn, "PRAGMA user_version"));
            assertEquals(List.of("Samples"), queryStrings(conn, "SELECT name FROM sqlite_schema WHERE type = 'table'"));
            conn.exec("INSERT INTO Samples VALUES (x'00', 1)");
        }
    }

    @Test
    void setupIsIdempotent() throws Exception {
        final List<String> schema;
        try (final SQLiteConnection conn = TestDatabases.attestation(dir)) {
            schema = schema(conn);
            conn.exec("INSERT INTO Configuration VALUES ('key', 'value')");
        }
        try (final SQLiteConnection conn = TestDatabases.attestation(dir);
                final SQLiteConnection samples = TestDatabases.samples(dir)) {
            assertEquals(schema, schema(conn));
            assertEquals(16, queryLong(conn, "PRAGMA user_version"));
            assertEquals("value", queryString(conn, "SELECT value FROM Configuration WHERE key = 'key'"));
            samples.exec("INSERT INTO Samples VALUES (x'00', 1)");
        }
        try (final SQLiteConnection samples = TestDatabases.samples(dir)) {
            assertEquals(1, queryLong(samples, "SELECT count(*) FROM Samples"));
        }
    }

    @Test
    void openConfiguresConnection() throws Exception {
        try (final SQLiteConnection conn = AttestationServer.open(dir.resolve("test.db").toFile())) {
            assertEquals(1, queryLong(conn, "PRAGMA foreign_keys"));
            assertEquals("wal", queryString(conn, "PRAGMA journal_mode"));
            assertEquals(0, queryLong(conn, "PRAGMA trusted_schema"));
            assertEquals(1024 * 1024 * 1024, queryLong(conn, "PRAGMA mmap_size"));
            assertEquals(10_000, queryLong(conn, "PRAGMA busy_timeout"));
        }
    }

    @Test
    void rollbackIfNeeded() throws Exception {
        try (final SQLiteConnection conn = AttestationServer.open(dir.resolve("test.db").toFile())) {
            conn.exec("CREATE TABLE t (x INTEGER)");
            AttestationServer.rollbackIfNeeded(conn);
            conn.exec("BEGIN; INSERT INTO t VALUES (1)");
            assertFalse(conn.getAutoCommit());
            AttestationServer.rollbackIfNeeded(conn);
            assertTrue(conn.getAutoCommit());
            assertEquals(0, queryLong(conn, "SELECT count(*) FROM t"));
        }
    }

    @Test
    void foreignKeysAreEnforced() throws Exception {
        try (final SQLiteConnection conn = TestDatabases.attestation(dir)) {
            final SQLiteException e = assertThrows(SQLiteException.class,
                    () -> conn.exec("INSERT INTO Sessions (userId, token, expiryTime) VALUES (1, x'00', 0)"));
            assertEquals(SQLITE_CONSTRAINT_FOREIGNKEY, e.getErrorCode());
        }
    }
}
