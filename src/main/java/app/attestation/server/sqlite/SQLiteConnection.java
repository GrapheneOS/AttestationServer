package app.attestation.server.sqlite;

import org.sqlite.jni.capi.CApi;
import org.sqlite.jni.capi.OutputPointer;
import org.sqlite.jni.capi.PrepareMultiCallback;
import org.sqlite.jni.capi.sqlite3;
import org.sqlite.jni.capi.sqlite3_stmt;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Objects;
import java.util.Set;

import static org.sqlite.jni.capi.CApi.SQLITE_MISUSE;
import static org.sqlite.jni.capi.CApi.SQLITE_OK;
import static org.sqlite.jni.capi.CApi.SQLITE_OPEN_CREATE;
import static org.sqlite.jni.capi.CApi.SQLITE_OPEN_EXRESCODE;
import static org.sqlite.jni.capi.CApi.SQLITE_OPEN_READWRITE;

public final class SQLiteConnection implements AutoCloseable {
    private final File file;
    private final Thread owner = Thread.currentThread();
    private final Set<SQLiteStatement> statements = Collections.newSetFromMap(new IdentityHashMap<>());
    private sqlite3 db;
    private boolean disposed;

    public SQLiteConnection(final File file) {
        this.file = Objects.requireNonNull(file);
    }

    public SQLiteConnection open() throws SQLiteException {
        checkThread();
        if (db != null || disposed) {
            throw new SQLiteException(SQLITE_MISUSE, "connection already opened (" + file + ")");
        }
        final OutputPointer.sqlite3 out = new OutputPointer.sqlite3();
        final int rc = CApi.sqlite3_open_v2(file.getAbsolutePath(), out,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_EXRESCODE, null);
        final sqlite3 handle = out.take();
        if (rc != SQLITE_OK) {
            final String message = handle != null ? CApi.sqlite3_errmsg(handle) : CApi.sqlite3_errstr(rc);
            CApi.sqlite3_close_v2(handle);
            throw new SQLiteException(rc, message + " (" + file + ")");
        }
        db = handle;
        return this;
    }

    public SQLiteConnection exec(final String sql) throws SQLiteException {
        final sqlite3 handle = handle();
        final int rc = CApi.sqlite3_prepare_multi(handle, sql,
                new PrepareMultiCallback.Finalize(new PrepareMultiCallback.StepAll()));
        if (rc != SQLITE_OK) {
            throw error(rc, sql);
        }
        return this;
    }

    public SQLiteStatement prepare(final String sql) throws SQLiteException {
        final sqlite3 handle = handle();
        final OutputPointer.sqlite3_stmt out = new OutputPointer.sqlite3_stmt();
        final int rc = CApi.sqlite3_prepare_v2(handle, sql, out);
        final sqlite3_stmt stmt = out.take();
        if (rc != SQLITE_OK) {
            throw error(rc, sql);
        }
        if (stmt == null) {
            throw new SQLiteException(SQLITE_MISUSE, "no SQL statement (" + sql + ")");
        }
        final SQLiteStatement statement = new SQLiteStatement(this, sql, stmt);
        statements.add(statement);
        return statement;
    }

    public SQLiteConnection setBusyTimeout(final long millis) throws SQLiteException {
        final int rc = CApi.sqlite3_busy_timeout(handle(), Math.clamp(millis, Integer.MIN_VALUE, Integer.MAX_VALUE));
        if (rc != SQLITE_OK) {
            throw error(rc, "setBusyTimeout(" + millis + ")");
        }
        return this;
    }

    public int getChanges() throws SQLiteException {
        return CApi.sqlite3_changes(handle());
    }

    public long getLastInsertId() throws SQLiteException {
        return CApi.sqlite3_last_insert_rowid(handle());
    }

    public boolean getAutoCommit() throws SQLiteException {
        return CApi.sqlite3_get_autocommit(handle());
    }

    public void dispose() {
        checkDisposeThread();
        disposed = true;
        if (db == null) {
            return;
        }
        for (final SQLiteStatement statement : new ArrayList<>(statements)) {
            statement.dispose();
        }
        CApi.sqlite3_close_v2(db);
        db = null;
    }

    @Override
    public void close() {
        dispose();
    }

    void checkThread() throws SQLiteException {
        if (Thread.currentThread() != owner) {
            throw new SQLiteException(SQLITE_MISUSE, "connection used from " + Thread.currentThread()
                    + " but is confined to " + owner + " (" + file + ")");
        }
    }

    sqlite3 handle() throws SQLiteException {
        checkThread();
        if (db == null) {
            throw new SQLiteException(SQLITE_MISUSE, (disposed ? "connection disposed" : "connection not opened")
                    + " (" + file + ")");
        }
        return db;
    }

    void forget(final SQLiteStatement statement) {
        statements.remove(statement);
    }

    SQLiteException error(final int rc, final String sql) {
        return new SQLiteException(rc, CApi.sqlite3_errmsg(db) + " (" + sql + ")");
    }

    void checkDisposeThread() {
        if (Thread.currentThread() != owner) {
            throw new IllegalStateException("connection disposed from " + Thread.currentThread()
                    + " but is confined to " + owner + " (" + file + ")");
        }
    }
}
