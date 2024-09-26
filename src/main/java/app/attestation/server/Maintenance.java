package app.attestation.server;

import com.almworks.sqlite4java.SQLiteBackup;
import com.almworks.sqlite4java.SQLiteConnection;
import com.almworks.sqlite4java.SQLiteException;
import com.almworks.sqlite4java.SQLiteStatement;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

import static app.attestation.server.SyslogLevel.CRIT;

class Maintenance implements Runnable {
    private static final long INITIAL_WAIT_MS = 60 * 1000;
    private static final long WAIT_MS = 24 * 60 * 60 * 1000;
    private static final long DELETE_EXPIRY_MS = 7L * 24 * 60 * 60 * 1000;
    private static final long INACTIVE_DEVICE_EXPIRY_MS = 90L * 24 * 60 * 60 * 1000;
    private static final boolean DELETE_INACTIVE_DEVICES = true;
    private static final long HISTORY_EXPIRY_MS = 180L * 24 * 60 * 60 * 1000;
    private static final boolean DELETE_LEGACY_HISTORY = true;
    private static final long INACTIVE_ACCOUNT_EXPIRY_MS = 365L * 24 * 60 * 60 * 1000;
    private static final boolean DELETE_INACTIVE_ACCOUNTS = true;

    private static final Logger logger = Logger.getLogger(Maintenance.class.getName());

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
        final SQLiteStatement deleteExpiredSessions;
        final SQLiteStatement deleteDeletedDevices;
        final SQLiteStatement deleteInactiveDevices;
        final SQLiteStatement deleteLegacyHistory;
        final SQLiteStatement deleteInactiveAccounts;
        try {
            deleteExpiredSessions = attestationConn.prepare("DELETE FROM Sessions WHERE expiryTime < ?");
            deleteDeletedDevices = attestationConn.prepare("DELETE FROM Devices WHERE deletionTime < ?");
            deleteInactiveDevices = attestationConn.prepare("DELETE FROM Devices WHERE verifiedTimeLast < ?");
            deleteLegacyHistory = attestationConn.prepare("DELETE FROM Attestations WHERE time < ?");
            deleteInactiveAccounts = attestationConn.prepare("DELETE FROM Accounts WHERE loginTime < ? " +
                    "AND NOT EXISTS (SELECT 1 FROM Devices WHERE Accounts.userId = Devices.userId)");
        } catch (final SQLiteException e) {
            attestationConn.dispose();
            samplesConn.dispose();
            logger.log(CRIT, "database error, cannot set up Maintenance thread", e);
            return;
        }

        while (true) {
            try {
                Thread.sleep(INITIAL_WAIT_MS);
            } catch (final InterruptedException e) {
                return;
            }

            logger.info("maintenance started");

            try {
                samplesConn.exec("VACUUM");

                final long now = System.currentTimeMillis();

                // This is also done as part of every login
                deleteExpiredSessions.bind(1, now);
                deleteExpiredSessions.step();

                deleteDeletedDevices.bind(1, now - DELETE_EXPIRY_MS);
                deleteDeletedDevices.step();

                if (DELETE_INACTIVE_DEVICES) {
                    deleteInactiveDevices.bind(1, now - INACTIVE_DEVICE_EXPIRY_MS);
                    deleteInactiveDevices.step();
                    logger.info("deleted " + attestationConn.getChanges() + " inactive devices");
                }

                if (DELETE_LEGACY_HISTORY) {
                    deleteLegacyHistory.bind(1, now - HISTORY_EXPIRY_MS);
                    deleteLegacyHistory.step();
                    logger.info("deleted " + attestationConn.getChanges() + " legacy history entries");
                }

                if (DELETE_INACTIVE_ACCOUNTS) {
                    deleteInactiveAccounts.bind(1, now - INACTIVE_ACCOUNT_EXPIRY_MS);
                    deleteInactiveAccounts.step();
                    logger.info("deleted " + attestationConn.getChanges() + " inactive accounts");
                }

                attestationConn.exec("ANALYZE");
                attestationConn.exec("VACUUM");
            } catch (final SQLiteException e) {
                logger.log(Level.WARNING, "database error", e);
            } finally {
                try {
                    deleteExpiredSessions.reset();
                    deleteDeletedDevices.reset();
                    deleteInactiveDevices.reset();
                    deleteLegacyHistory.reset();
                    deleteInactiveAccounts.reset();
                } catch (final SQLiteException e) {
                    logger.log(Level.WARNING, "database error", e);
                }
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
