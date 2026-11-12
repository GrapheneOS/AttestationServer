package app.attestation.server.sqlite;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static app.attestation.server.sqlite.SQLiteAssertions.assertCode;
import static app.attestation.server.sqlite.SQLiteAssertions.assertThrowsOnOtherThread;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.sqlite.jni.capi.CApi.SQLITE_CONSTRAINT_UNIQUE;
import static org.sqlite.jni.capi.CApi.SQLITE_ERROR;
import static org.sqlite.jni.capi.CApi.SQLITE_MISUSE;
import static org.sqlite.jni.capi.CApi.SQLITE_RANGE;

class SQLiteStatementTest {
    @TempDir
    Path dir;

    private SQLiteConnection conn;

    @BeforeEach
    void open() throws SQLiteException {
        conn = new SQLiteConnection(dir.resolve("test.db").toFile()).open();
    }

    @AfterEach
    void close() {
        conn.dispose();
    }

    @Test
    void integerRoundTrip() throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare("SELECT ?, ?, ?, ?, typeof(?1)")) {
            assertSame(st, st.bind(1, Integer.MIN_VALUE));
            st.bind(2, Integer.MAX_VALUE);
            st.bind(3, Long.MIN_VALUE);
            st.bind(4, Long.MAX_VALUE);
            assertTrue(st.step());
            assertEquals(Integer.MIN_VALUE, st.columnInt(0));
            assertEquals(Integer.MAX_VALUE, st.columnInt(1));
            assertEquals(Long.MIN_VALUE, st.columnLong(2));
            assertEquals(Long.MAX_VALUE, st.columnLong(3));
            assertEquals("integer", st.columnString(4));
            assertEquals(Integer.MIN_VALUE, st.columnLong(0));
            assertFalse(st.step());
        }
    }

    @Test
    void byteArgumentBindsInteger() throws SQLiteException {
        final byte value = -2;
        try (final SQLiteStatement st = conn.prepare("SELECT ?1, typeof(?1)")) {
            st.bind(1, value);
            assertTrue(st.step());
            assertEquals(-2, st.columnInt(0));
            assertEquals("integer", st.columnString(1));
        }
    }

    @Test
    void stringRoundTrip() throws SQLiteException {
        final String value = "a\u00e9\u4e2d\ud83d\ude00\ud834\udd1e";
        try (final SQLiteStatement st = conn.prepare("SELECT ?1, typeof(?1), length(?1), hex(?1)")) {
            st.bind(1, value);
            assertTrue(st.step());
            assertEquals(value, st.columnString(0));
            assertEquals("text", st.columnString(1));
            assertEquals(5, st.columnInt(2));
            assertEquals("61C3A9E4B8ADF09F9880F09D849E", st.columnString(3));
        }
    }

    @Test
    void storedStringRoundTrip() throws SQLiteException {
        final String value = "\ud83d\ude00 emoji";
        conn.exec("CREATE TABLE t (x TEXT NOT NULL)");
        try (final SQLiteStatement insert = conn.prepare("INSERT INTO t VALUES (?)")) {
            insert.bind(1, value);
            assertFalse(insert.step());
        }
        try (final SQLiteStatement select = conn.prepare("SELECT x, length(x) FROM t")) {
            assertTrue(select.step());
            assertEquals(value, select.columnString(0));
            assertEquals(7, select.columnInt(1));
        }
    }

    @Test
    void emptyString() throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare("SELECT ?1, typeof(?1), length(?1)")) {
            st.bind(1, "");
            assertTrue(st.step());
            assertEquals("", st.columnString(0));
            assertFalse(st.columnNull(0));
            assertEquals("text", st.columnString(1));
            assertEquals(0, st.columnInt(2));
        }
    }

    @Test
    void blobRoundTrip() throws SQLiteException {
        final byte[] value = {0, 1, -1, 127, -128, 0};
        try (final SQLiteStatement st = conn.prepare("SELECT ?1, typeof(?1), length(?1)")) {
            st.bind(1, value);
            assertTrue(st.step());
            assertArrayEquals(value, st.columnBlob(0));
            assertEquals("blob", st.columnString(1));
            assertEquals(value.length, st.columnInt(2));
        }
    }

    @Test
    void emptyBlob() throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare("SELECT ?1, typeof(?1), x''")) {
            st.bind(1, new byte[0]);
            assertTrue(st.step());
            assertArrayEquals(new byte[0], st.columnBlob(0));
            assertFalse(st.columnNull(0));
            assertEquals("blob", st.columnString(1));
            assertArrayEquals(new byte[0], st.columnBlob(2));
        }
    }

    @Test
    void nullValues() throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare("SELECT ?1, ?2, ?3, typeof(?1), typeof(?2), typeof(?3)")) {
            st.bind(1, (String) null);
            st.bind(2, (byte[]) null);
            assertTrue(st.step());
            for (int i = 0; i < 3; i++) {
                assertTrue(st.columnNull(i));
                assertEquals(0, st.columnInt(i));
                assertEquals(0, st.columnLong(i));
                assertNull(st.columnString(i));
                assertNull(st.columnBlob(i));
                assertEquals("null", st.columnString(3 + i));
            }
        }
    }

    @Test
    void bindingReplacesPreviousValue() throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare("SELECT ?")) {
            st.bind(1, "text");
            st.bind(1, 5);
            assertTrue(st.step());
            assertEquals(5, st.columnInt(0));
        }
    }

    @Test
    void resetClearsBindingsAndRow() throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare("SELECT ?")) {
            st.bind(1, 42);
            assertTrue(st.step());
            assertEquals(42, st.columnInt(0));
            assertSame(st, st.reset());
            assertCode(SQLITE_MISUSE, () -> st.columnInt(0));
            assertTrue(st.step());
            assertTrue(st.columnNull(0));
        }
    }

    @Test
    void stepAfterDoneRunsAgain() throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare("SELECT 7")) {
            assertTrue(st.step());
            assertFalse(st.step());
            assertCode(SQLITE_MISUSE, () -> st.columnInt(0));
            assertTrue(st.step());
            assertEquals(7, st.columnInt(0));
        }
    }

    @Test
    void bindWhileRunningFails() throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare("SELECT ?")) {
            assertTrue(st.step());
            assertCode(SQLITE_MISUSE, () -> st.bind(1, 1));
            st.reset();
            st.bind(1, 1);
        }
    }

    @Test
    void columnAccessRequiresRow() throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare("SELECT 1")) {
            assertCode(SQLITE_MISUSE, () -> st.columnInt(0));
            assertCode(SQLITE_MISUSE, () -> st.columnLong(0));
            assertCode(SQLITE_MISUSE, () -> st.columnString(0));
            assertCode(SQLITE_MISUSE, () -> st.columnBlob(0));
            assertCode(SQLITE_MISUSE, () -> st.columnNull(0));
        }
    }

    @Test
    void columnIndexOutOfRange() throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare("SELECT 1, 2")) {
            assertTrue(st.step());
            assertCode(SQLITE_MISUSE, () -> st.columnInt(-1));
            assertCode(SQLITE_MISUSE, () -> st.columnInt(2));
            assertCode(SQLITE_MISUSE, () -> st.columnNull(2));
            assertCode(SQLITE_MISUSE, () -> st.columnBlob(2));
            assertEquals(2, st.columnInt(1));
        }
    }

    @Test
    void bindIndexOutOfRange() throws SQLiteException {
        try (final SQLiteStatement st = conn.prepare("SELECT ?")) {
            assertCode(SQLITE_RANGE, () -> st.bind(0, 1));
            assertCode(SQLITE_RANGE, () -> st.bind(2, 1L));
            assertCode(SQLITE_RANGE, () -> st.bind(2, "x"));
            assertCode(SQLITE_RANGE, () -> st.bind(2, new byte[1]));
        }
    }

    @Test
    void failedStepClearsRow() throws SQLiteException {
        conn.exec("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1), (-9223372036854775807 - 1)");
        try (final SQLiteStatement st = conn.prepare("SELECT abs(x) FROM t ORDER BY rowid")) {
            assertTrue(st.step());
            assertEquals(1, st.columnInt(0));
            final SQLiteException e = assertCode(SQLITE_ERROR, st::step);
            assertTrue(e.getMessage().contains("integer overflow"), e.getMessage());
            assertCode(SQLITE_MISUSE, () -> st.columnInt(0));
            st.reset();
            assertTrue(st.step());
        }
    }

    @Test
    void uniqueViolationReportsExtendedCode() throws SQLiteException {
        conn.exec("CREATE TABLE t (x INTEGER UNIQUE)");
        try (final SQLiteStatement st = conn.prepare("INSERT INTO t VALUES (?)")) {
            st.bind(1, 1);
            assertFalse(st.step());
            st.reset();
            st.bind(1, 1);
            final SQLiteException e = assertCode(SQLITE_CONSTRAINT_UNIQUE, st::step);
            assertTrue(e.getMessage().contains("UNIQUE constraint failed: t.x"), e.getMessage());
            assertTrue(e.getMessage().contains("INSERT INTO t VALUES (?)"), e.getMessage());
            st.reset();
            st.bind(1, 2);
            assertFalse(st.step());
        }
        assertEquals(1, conn.getChanges());
    }

    @Test
    void disposeIsIdempotentAndBlocksUse() throws SQLiteException {
        final SQLiteStatement st = conn.prepare("SELECT ?");
        st.dispose();
        st.dispose();
        st.close();
        assertCode(SQLITE_MISUSE, () -> st.bind(1, 1));
        assertCode(SQLITE_MISUSE, st::step);
        assertCode(SQLITE_MISUSE, st::reset);
        assertCode(SQLITE_MISUSE, () -> st.columnInt(0));
        conn.exec("VACUUM");
    }

    @Test
    void wrongThreadUseFails() throws Exception {
        try (final SQLiteStatement st = conn.prepare("SELECT ?")) {
            assertEquals(SQLITE_MISUSE, assertThrowsOnOtherThread(SQLiteException.class, () -> st.bind(1, 1))
                    .getErrorCode());
            assertEquals(SQLITE_MISUSE, assertThrowsOnOtherThread(SQLiteException.class, st::step).getErrorCode());
            assertThrowsOnOtherThread(IllegalStateException.class, st::dispose);
            st.bind(1, 3);
            assertTrue(st.step());
            assertEquals(3, st.columnInt(0));
        }
    }
}
