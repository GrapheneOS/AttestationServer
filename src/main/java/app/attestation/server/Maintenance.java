package app.attestation.server;

import app.attestation.server.sqlite.SQLiteConnection;
import app.attestation.server.sqlite.SQLiteException;
import app.attestation.server.sqlite.SQLiteStatement;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

import static app.attestation.server.SyslogLevel.CRIT;

class Maintenance implements Runnable {
    private static final long INITIAL_WAIT_MS = 5 * 60 * 1000;
    private static final long WAIT_MS = 24 * 60 * 60 * 1000;
    private static final long DELETE_EXPIRY_MS = 7L * 24 * 60 * 60 * 1000;
    private static final long INACTIVE_DEVICE_EXPIRY_MS = 90L * 24 * 60 * 60 * 1000;
    private static final boolean DELETE_INACTIVE_DEVICES = true;
    private static final long HISTORY_EXPIRY_MS = 180L * 24 * 60 * 60 * 1000;
    private static final boolean DELETE_LEGACY_HISTORY = true;
    private static final long INACTIVE_ACCOUNT_EXPIRY_MS = 365L * 24 * 60 * 60 * 1000;
    private static final boolean DELETE_INACTIVE_ACCOUNTS = true;

    private static final Logger logger = Logger.getLogger(Maintenance.class.getName());

    static void maintain(final SQLiteConnection samplesConn, final SQLiteConnection attestationConn,
            final long now) throws SQLiteException {
        samplesConn.exec("VACUUM");

        // This is also done as part of every login
        final SQLiteStatement deleteExpiredSessions =
                attestationConn.prepare("DELETE FROM Sessions WHERE expiryTime < ?");
        try {
            deleteExpiredSessions.bind(1, now);
            deleteExpiredSessions.step();
        } finally {
            deleteExpiredSessions.dispose();
        }

        final SQLiteStatement deleteDeletedDevices =
                attestationConn.prepare("DELETE FROM Devices WHERE deletionTime < ?");
        try {
            deleteDeletedDevices.bind(1, now - DELETE_EXPIRY_MS);
            deleteDeletedDevices.step();
        } finally {
            deleteDeletedDevices.dispose();
        }

        if (DELETE_INACTIVE_DEVICES) {
            final SQLiteStatement deleteInactiveDevices =
                    attestationConn.prepare("DELETE FROM Devices WHERE verifiedTimeLast < ?");
            try {
                deleteInactiveDevices.bind(1, now - INACTIVE_DEVICE_EXPIRY_MS);
                deleteInactiveDevices.step();
            } finally {
                deleteInactiveDevices.dispose();
            }
            logger.info("deleted " + attestationConn.getChanges() + " inactive devices");
        }

        if (DELETE_LEGACY_HISTORY) {
            final SQLiteStatement deleteLegacyHistory =
                    attestationConn.prepare("DELETE FROM Attestations WHERE time < ?");
            try {
                deleteLegacyHistory.bind(1, now - HISTORY_EXPIRY_MS);
                deleteLegacyHistory.step();
            } finally {
                deleteLegacyHistory.dispose();
            }
            logger.info("deleted " + attestationConn.getChanges() + " legacy history entries");
        }

        if (DELETE_INACTIVE_ACCOUNTS) {
            final SQLiteStatement deleteInactiveAccounts = attestationConn.prepare("""
                    DELETE FROM Accounts WHERE loginTime < ? AND NOT EXISTS
                        (SELECT 1 FROM Devices WHERE Accounts.userId = Devices.userId)""");
            try {
                deleteInactiveAccounts.bind(1, now - INACTIVE_ACCOUNT_EXPIRY_MS);
                deleteInactiveAccounts.step();
            } finally {
                deleteInactiveAccounts.dispose();
            }
            logger.info("deleted " + attestationConn.getChanges() + " inactive accounts");
        }

        attestationConn.exec("ANALYZE");
        attestationConn.exec("VACUUM");
    }

    @Override
    public void run() {
        final SQLiteConnection samplesConn;
        final SQLiteConnection attestationConn;
        try {
            samplesConn = AttestationServer.open(AttestationServer.SAMPLES_DATABASE);
            attestationConn = AttestationServer.open(AttestationServer.ATTESTATION_DATABASE);
        } catch (final SQLiteException e) {
            logger.log(CRIT, "database error, cannot set up Maintenance thread", e);
            return;
        }

        try {
            Thread.sleep(INITIAL_WAIT_MS);
        } catch (final InterruptedException e) {
            return;
        }

        while (true) {
            logger.info("maintenance started");

            try {
                maintain(samplesConn, attestationConn, System.currentTimeMillis());
            } catch (final SQLiteException e) {
                logger.log(Level.WARNING, "database error", e);
            }

            logger.info("maintenance completed");

            try {
                Thread.sleep(WAIT_MS);
            } catch (final InterruptedException e) {
                return;
            }
        }
    }
}
