package app.attestation.server.sqlite;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.sqlite.jni.capi.CApi;
import org.sqlite.jni.capi.OutputPointer;

import java.io.File;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static app.attestation.server.sqlite.SQLiteAssertions.assertCode;
import static app.attestation.server.sqlite.SQLiteAssertions.assertThrowsOnOtherThread;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.sqlite.jni.capi.CApi.SQLITE_BUSY;
import static org.sqlite.jni.capi.CApi.SQLITE_CANTOPEN;
import static org.sqlite.jni.capi.CApi.SQLITE_CONSTRAINT_UNIQUE;
import static org.sqlite.jni.capi.CApi.SQLITE_ERROR;
import static org.sqlite.jni.capi.CApi.SQLITE_MISUSE;
import static org.sqlite.jni.capi.CApi.SQLITE_OK;
import static org.sqlite.jni.capi.CApi.SQLITE_STATUS_MEMORY_USED;

class SQLiteConnectionTest {
    @TempDir
    Path dir;

    private File file() {
        return dir.resolve("test.db").toFile();
    }

    private static long queryLong(final SQLiteConnection conn, final String sql) throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare(sql)) {
            assertTrue(st.step());
            return st.columnLong(0);
        }
    }

    private static String queryString(final SQLiteConnection conn, final String sql) throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare(sql)) {
            assertTrue(st.step());
            return st.columnString(0);
        }
    }

    private long memoryUsedAfterWarmUp() throws SQLiteException {
        try (final SQLiteConnection conn = new SQLiteConnection(file()).open()) {
            conn.prepare("SELECT 1").dispose();
        }
        return memoryUsed();
    }

    private static long memoryUsed() {
        final OutputPointer.Int64 current = new OutputPointer.Int64();
        assertEquals(SQLITE_OK, CApi.sqlite3_status64(SQLITE_STATUS_MEMORY_USED, current,
                new OutputPointer.Int64(), false));
        return current.value;
    }

    @Test
    void bundledLibraryVersion() throws SQLiteException {
        try (final SQLiteConnection conn = new SQLiteConnection(file()).open()) {
            assertEquals("3.54.0", queryString(conn, "SELECT sqlite_version()"));
        }
    }

    @Test
    void compileOptions() throws SQLiteException {
        try (final SQLiteConnection conn = new SQLiteConnection(file()).open()) {
            final Set<String> options = new HashSet<>();
            try (final SQLiteStatement st = conn.prepare("PRAGMA compile_options")) {
                while (st.step()) {
                    options.add(st.columnString(0));
                }
            }
            assertTrue(options.containsAll(Set.of("THREADSAFE=1", "DQS=0", "OMIT_DEPRECATED", "TEMP_STORE=1",
                    "DEFAULT_CACHE_SIZE=-2000", "DEFAULT_PAGE_SIZE=4096", "ENABLE_RTREE",
                    "ENABLE_COLUMN_METADATA", "ENABLE_MEMORY_MANAGEMENT")), options::toString);
            assertFalse(options.contains("ENABLE_FTS5"), options::toString);
            assertFalse(options.contains("ENABLE_MATH_FUNCTIONS"), options::toString);

            assertEquals(0, queryLong(conn, "PRAGMA trusted_schema"));
            assertEquals(-2000, queryLong(conn, "PRAGMA cache_size"));
            conn.exec("PRAGMA writable_schema = ON");
            assertEquals(0, queryLong(conn, "PRAGMA writable_schema"));
            assertCode(SQLITE_ERROR, () -> conn.prepare("SELECT \"missing\""));
            assertCode(SQLITE_ERROR, () -> conn.prepare("SELECT sqrt(4)"));
        }
    }

    @Test
    void lifecycle() throws Exception {
        final SQLiteConnection conn = new SQLiteConnection(file());
        assertCode(SQLITE_MISUSE, () -> conn.exec("SELECT 1"));
        assertCode(SQLITE_MISUSE, () -> conn.prepare("SELECT 1"));
        assertEquals(SQLITE_MISUSE, assertThrowsOnOtherThread(SQLiteException.class, conn::open).getErrorCode());
        assertSame(conn, conn.open());
        assertCode(SQLITE_MISUSE, conn::open);
        conn.dispose();
        conn.dispose();
        conn.close();
        assertCode(SQLITE_MISUSE, () -> conn.exec("SELECT 1"));
        assertCode(SQLITE_MISUSE, conn::getAutoCommit);
        assertCode(SQLITE_MISUSE, conn::open);

        final SQLiteConnection unopened = new SQLiteConnection(file());
        unopened.dispose();
        assertCode(SQLITE_MISUSE, unopened::open);
    }

    @Test
    void openFailureReleasesHandle() throws SQLiteException {
        final long before = memoryUsedAfterWarmUp();
        final SQLiteConnection conn = new SQLiteConnection(dir.toFile());
        final SQLiteException e = assertThrows(SQLiteException.class, conn::open);
        assertEquals(SQLITE_CANTOPEN, e.getErrorCode() & 0xff, e.getMessage());
        assertTrue(e.getMessage().contains(dir.toString()), e.getMessage());
        assertEquals(before, memoryUsed());
        conn.dispose();
    }

    @Test
    void disposeFinalizesOutstandingStatements() throws SQLiteException {
        final long before = memoryUsedAfterWarmUp();
        final SQLiteConnection conn = new SQLiteConnection(file()).open();
        conn.exec("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1), (2)");
        final SQLiteStatement stepped = conn.prepare("SELECT x FROM t");
        assertTrue(stepped.step());
        final SQLiteStatement idle = conn.prepare("SELECT ?");
        idle.bind(1, "value");
        conn.dispose();
        assertEquals(before, memoryUsed());
        assertCode(SQLITE_MISUSE, stepped::step);
        assertCode(SQLITE_MISUSE, () -> idle.bind(1, 1));
        stepped.dispose();
        idle.dispose();
    }

    @Test
    void execRunsScripts() throws SQLiteException {
        try (final SQLiteConnection conn = new SQLiteConnection(file()).open()) {
            assertSame(conn, conn.exec("""
                    -- leading comment
                    PRAGMA journal_mode = WAL;
                    CREATE TABLE t (x INTEGER);
                    INSERT INTO t VALUES (1), (2);
                    SELECT * FROM t;
                    PRAGMA user_version = 3;
                    """));
            assertEquals("wal", queryString(conn, "PRAGMA journal_mode"));
            assertEquals(2, queryLong(conn, "SELECT count(*) FROM t"));
            assertEquals(3, queryLong(conn, "PRAGMA user_version"));
            conn.exec("");
            conn.exec("  -- only a comment\n");
            conn.exec("VACUUM");
        }
    }

    @Test
    void execStopsAtPrepareError() throws SQLiteException {
        try (final SQLiteConnection conn = new SQLiteConnection(file()).open()) {
            conn.exec("CREATE TABLE t (x INTEGER)");
            final String sql = "INSERT INTO t VALUES (1); INSERT INTO missing VALUES (2); INSERT INTO t VALUES (3)";
            final SQLiteException e = assertCode(SQLITE_ERROR, () -> conn.exec(sql));
            assertTrue(e.getMessage().contains("no such table: missing"), e.getMessage());
            assertTrue(e.getMessage().contains(sql), e.getMessage());
            assertEquals(1, queryLong(conn, "SELECT count(*) FROM t"));
            assertTrue(conn.getAutoCommit());
            conn.exec("VACUUM");
        }
    }

    @Test
    void execStopsAtStepError() throws SQLiteException {
        try (final SQLiteConnection conn = new SQLiteConnection(file()).open()) {
            final SQLiteException e = assertCode(SQLITE_CONSTRAINT_UNIQUE, () -> conn.exec("""
                    CREATE TABLE t (x INTEGER UNIQUE);
                    INSERT INTO t VALUES (1);
                    INSERT INTO t VALUES (1);
                    INSERT INTO t VALUES (2);
                    """));
            assertTrue(e.getMessage().contains("UNIQUE constraint failed: t.x"), e.getMessage());
            assertEquals(1, queryLong(conn, "SELECT count(*) FROM t"));
            conn.exec("VACUUM");
        }
    }

    @Test
    void prepareErrors() throws SQLiteException {
        try (final SQLiteConnection conn = new SQLiteConnection(file()).open()) {
            assertCode(SQLITE_MISUSE, () -> conn.prepare(""));
            assertCode(SQLITE_MISUSE, () -> conn.prepare("  -- only a comment\n"));
            final SQLiteException e = assertCode(SQLITE_ERROR, () -> conn.prepare("SELEC 1"));
            assertTrue(e.getMessage().contains("near \"SELEC\": syntax error"), e.getMessage());
            assertTrue(e.getMessage().contains("SELEC 1"), e.getMessage());
            conn.exec("VACUUM");
        }
    }

    @Test
    void changesLastInsertIdAndAutoCommit() throws SQLiteException {
        try (final SQLiteConnection conn = new SQLiteConnection(file()).open()) {
            conn.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, x INTEGER)");
            conn.exec("INSERT INTO t (id, x) VALUES (10, 1), (20, 1), (30, 2)");
            assertEquals(3, conn.getChanges());
            assertEquals(30, conn.getLastInsertId());
            conn.exec("UPDATE t SET x = 0 WHERE x = 1");
            assertEquals(2, conn.getChanges());
            assertEquals(30, conn.getLastInsertId());

            assertTrue(conn.getAutoCommit());
            conn.exec("BEGIN");
            assertFalse(conn.getAutoCommit());
            conn.exec("ROLLBACK");
            assertTrue(conn.getAutoCommit());
        }
    }

    @Test
    void busyTimeout() throws SQLiteException {
        try (final SQLiteConnection first = new SQLiteConnection(file()).open();
                final SQLiteConnection second = new SQLiteConnection(file()).open()) {
            first.exec("PRAGMA journal_mode = WAL");
            first.exec("BEGIN IMMEDIATE");
            assertSame(second, second.setBusyTimeout(200));
            final long start = System.nanoTime();
            assertCode(SQLITE_BUSY, () -> second.exec("BEGIN IMMEDIATE"));
            final long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            assertTrue(elapsedMs >= 100 && elapsedMs < 10_000, elapsedMs + " ms");
            first.exec("COMMIT");
            second.exec("BEGIN IMMEDIATE; COMMIT");

            second.setBusyTimeout(Long.MAX_VALUE);
            second.setBusyTimeout(-1);
        }
    }

    @Test
    void wrongThreadUseFails() throws Exception {
        try (final SQLiteConnection conn = new SQLiteConnection(file()).open()) {
            for (final Executable executable : List.<Executable>of(
                    () -> conn.exec("SELECT 1"),
                    () -> conn.prepare("SELECT 1"),
                    () -> conn.setBusyTimeout(1),
                    conn::getChanges,
                    conn::getLastInsertId,
                    conn::getAutoCommit,
                    conn::open)) {
                assertEquals(SQLITE_MISUSE,
                        assertThrowsOnOtherThread(SQLiteException.class, executable).getErrorCode());
            }
            assertThrowsOnOtherThread(IllegalStateException.class, conn::dispose);
            assertThrowsOnOtherThread(IllegalStateException.class, conn::close);
            conn.exec("SELECT 1");
        }
    }
}
