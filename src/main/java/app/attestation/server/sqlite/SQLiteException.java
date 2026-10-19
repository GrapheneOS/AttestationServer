package app.attestation.server.sqlite;

public final class SQLiteException extends Exception {
    private final int errorCode;

    public SQLiteException(final int errorCode, final String message) {
        super("[" + errorCode + "] " + message);
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
