package app.attestation.server.sqlite;

import org.junit.jupiter.api.function.Executable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class SQLiteAssertions {
    private SQLiteAssertions() {}

    static SQLiteException assertCode(final int expected, final Executable executable) {
        final SQLiteException e = assertThrows(SQLiteException.class, executable);
        assertEquals(expected, e.getErrorCode(), e.getMessage());
        return e;
    }

    static <T extends Throwable> T assertThrowsOnOtherThread(final Class<T> expected, final Executable executable)
            throws InterruptedException {
        final Throwable[] thrown = new Throwable[1];
        final Thread thread = new Thread(() -> {
            try {
                executable.execute();
            } catch (final Throwable t) {
                thrown[0] = t;
            }
        });
        thread.start();
        thread.join();
        return assertInstanceOf(expected, thrown[0]);
    }
}
