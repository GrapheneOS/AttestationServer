package app.attestation.server.sqlite;

import org.sqlite.jni.capi.CApi;
import org.sqlite.jni.capi.sqlite3_stmt;

import static org.sqlite.jni.capi.CApi.SQLITE_BLOB;
import static org.sqlite.jni.capi.CApi.SQLITE_DONE;
import static org.sqlite.jni.capi.CApi.SQLITE_MISUSE;
import static org.sqlite.jni.capi.CApi.SQLITE_NULL;
import static org.sqlite.jni.capi.CApi.SQLITE_OK;
import static org.sqlite.jni.capi.CApi.SQLITE_ROW;

public final class SQLiteStatement implements AutoCloseable {
    private final SQLiteConnection connection;
    private final String sql;
    private sqlite3_stmt stmt;
    private boolean hasRow;

    SQLiteStatement(final SQLiteConnection connection, final String sql, final sqlite3_stmt stmt) {
        this.connection = connection;
        this.sql = sql;
        this.stmt = stmt;
    }

    public SQLiteStatement bind(final int index, final int value) throws SQLiteException {
        return checkBind(CApi.sqlite3_bind_int(handle(), index, value));
    }

    public SQLiteStatement bind(final int index, final long value) throws SQLiteException {
        return checkBind(CApi.sqlite3_bind_int64(handle(), index, value));
    }

    public SQLiteStatement bind(final int index, final String value) throws SQLiteException {
        return checkBind(CApi.sqlite3_bind_text16(handle(), index, value));
    }

    public SQLiteStatement bind(final int index, final byte[] value) throws SQLiteException {
        return checkBind(CApi.sqlite3_bind_blob(handle(), index, value));
    }

    public boolean step() throws SQLiteException {
        final sqlite3_stmt handle = handle();
        hasRow = false;
        final int rc = CApi.sqlite3_step(handle);
        if (rc == SQLITE_ROW) {
            hasRow = true;
            return true;
        }
        if (rc == SQLITE_DONE) {
            return false;
        }
        throw connection.error(rc, sql);
    }

    public SQLiteStatement reset() throws SQLiteException {
        final sqlite3_stmt handle = handle();
        hasRow = false;
        CApi.sqlite3_reset(handle);
        final int rc = CApi.sqlite3_clear_bindings(handle);
        if (rc != SQLITE_OK) {
            throw connection.error(rc, sql);
        }
        return this;
    }

    public int columnInt(final int column) throws SQLiteException {
        return CApi.sqlite3_column_int(row(column), column);
    }

    public long columnLong(final int column) throws SQLiteException {
        return CApi.sqlite3_column_int64(row(column), column);
    }

    public String columnString(final int column) throws SQLiteException {
        return CApi.sqlite3_column_text16(row(column), column);
    }

    public byte[] columnBlob(final int column) throws SQLiteException {
        final sqlite3_stmt handle = row(column);
        final int type = CApi.sqlite3_column_type(handle, column);
        final byte[] value = CApi.sqlite3_column_blob(handle, column);
        return value == null && type == SQLITE_BLOB ? new byte[0] : value;
    }

    public boolean columnNull(final int column) throws SQLiteException {
        return CApi.sqlite3_column_type(row(column), column) == SQLITE_NULL;
    }

    public void dispose() {
        connection.checkDisposeThread();
        if (stmt == null) {
            return;
        }
        connection.forget(this);
        CApi.sqlite3_finalize(stmt);
        stmt = null;
        hasRow = false;
    }

    @Override
    public void close() {
        dispose();
    }

    private sqlite3_stmt handle() throws SQLiteException {
        connection.checkThread();
        if (stmt == null) {
            throw new SQLiteException(SQLITE_MISUSE, "statement disposed (" + sql + ")");
        }
        return stmt;
    }

    private SQLiteStatement checkBind(final int rc) throws SQLiteException {
        if (rc != SQLITE_OK) {
            throw connection.error(rc, sql);
        }
        return this;
    }

    private sqlite3_stmt row(final int column) throws SQLiteException {
        final sqlite3_stmt handle = handle();
        if (!hasRow) {
            throw new SQLiteException(SQLITE_MISUSE, "no current row (" + sql + ")");
        }
        final int count = CApi.sqlite3_column_count(handle);
        if (column < 0 || column >= count) {
            throw new SQLiteException(SQLITE_MISUSE, "column " + column + " out of range for " + count
                    + " columns (" + sql + ")");
        }
        return handle;
    }
}
